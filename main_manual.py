import json
import os
import sys
from crypto import rsa_key_generation, split_secret, recover_secret, hybrid_encrypt, hybrid_decrypt, encrypt_private_key, decrypt_private_key
from actors import IdentityProvider, DigitalUrna, Elettore, SecurityError
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_der_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

print("|| SIMULAZIONE ELEZIONI DEL CONSIGLIO STUDENTESCO ||\n")
lista_candidati = {
    "Terranova": 0,
    "Bodenizza": 0,
    "Esposito": 0,
    "Iannone": 0,
    "Azzato": 0
}

print("candidati alle elezioni:")
for c in lista_candidati:
    print(c)

print("\n[1] CONFIGURAZIONE COMMISSIONE")
sk_commissione, pk_commissione = rsa_key_generation()

sk_bytes = sk_commissione.private_bytes(
    Encoding.DER,
    PrivateFormat.PKCS8,
    NoEncryption()
)

chiave_scrutinio = AESGCM.generate_key(bit_length=128)

sk_commissione_cifrata = encrypt_private_key(
    sk_bytes,
    chiave_scrutinio
)

segreto_scrutinio = int.from_bytes(
    chiave_scrutinio,
    'big'
)

try:
    n_membri = int(input("inserire il numero totale di membri della Commissione di Scrutinio: "))
    t_membri_necessari = int(input("inserire il numero di membri sufficienti per lo Scrutinio: "))
    if(n_membri < t_membri_necessari):
        print("il numero totale di membri deve essere superiore a quello sufficiente per lo scrutinio")
        sys.exit()
except:
    print("inserire valori interi")
    sys.exit()

frammenti = split_secret(
    segreto_scrutinio,
    t=t_membri_necessari,
    n=n_membri
)

sk_commissione = None
print(f"Chiave di scrutinio divisa in {n_membri} parti con successo, {t_membri_necessari}/{n_membri} parti sufficienti per la ricostruzione\n")

print("[2] INIZIALIZZAZIONE SERVER")
idp = IdentityProvider()
urna = DigitalUrna(idp_pk=idp.chiave_pubblica)
print("Identity Provider e Urna correttamente attivati e disponibili!\n")

print("[3] APERTURA SEGGIO")
try:
    num_elettori = int(input("Inserire il numero di studenti elettori: "))
except:
    print("Errore: Il numero di elettori deve essere un intero!")

for i in range(num_elettori):
    print(f"Accesso Studente {i}")
    username = input("Inserire username: ")
    password = input("Inserire password: ")
    client = Elettore(username,password)
    voto = input("Inserire la preferenza di voto: ")
    try:
        ricevuta = client.voto(voto, idp, urna, pk_commissione)
        print(f"Voto accettato! Indice: {ricevuta['index']}, merkle root: {ricevuta['merkle_root_corrente'][:10]}")

    except PermissionError as e:
        print(f"[AUTH ERROR] {e}")
        continue

    except SecurityError as e:
        print(f"[SECURITY ERROR] {e}")
        continue

    except Exception as e:
        print(f"[UNKNOWN ERROR] {e}")
        continue

print("\n[4] FASE DI ATTACCO AL SISTEMA")

try:
    ask_attack = int(input("si desidera attaccare il sistema?\n0. si\n1. no\n"))
except:
    print("Errore: inserire uno degli interi proposti!")
    sys.exit()

if ask_attack == 0:
    try:
        attack_type = int(input("\nscegliere il tipo di attacco:\n0. double-vote\n1. man in the middle\n2. bypass token idp\n3. gestore malevolo\n"))
    except:
        print("Errore: inserire uno degli interi proposti!")
        sys.exit()
    if attack_type == 0:
        try:
            dv_username = input("inserire username: ")
            dv_password = input("inserire password: ")
            dv_voto = input("inserire voto: ")
            elettore = Elettore(dv_username,dv_password)
            elettore.voto(dv_voto,idp,urna,pk_commissione)
            print("Questo studente non aveva ancora votato! Voto registrato con successo")
        except ValueError as e:
            print(f"{e}")
        except PermissionError as e:
            print(f"[AUTH ERROR] {e}")
    # da fixare la dimostrazione del mitm        
    elif attack_type == 1:
        try:
            username = input("Username vittima: ")
            password = input("Password vittima: ")
            voto_originale = input("Voto originale (quello che l'utente vorrebbe esprimere): ")
            voto_alterato = input("Voto che l'attaccante vuole forzare: ")

            vittima = Elettore(username, password)
            pk_e = vittima.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

            token_idp = idp.authenticate_and_sign_key(username, password, pk_e)

            tx_legittima = {
                "chiave_effimera": pk_e,
                "token_idp": token_idp,
                "voto": hybrid_encrypt(voto_originale, pk_commissione)
            }

            print("Intercettazione pacchetto in corso...")

            tx_intercettata = tx_legittima.copy()
            tx_intercettata["voto"] = hybrid_encrypt(voto_alterato, pk_commissione)

            print("Pacchetto intercettato dal mitm modificato e reinviato all'urna...")

            urna.get_tx_vote(tx_intercettata)

            print("ERRORE: transazione modificata accettata, il sistema ha fallito!")

        except (SecurityError, Exception) as e:
            print(f"MITM bloccato: {e}")
        except PermissionError as e:
            print(f"[AUTH ERROR] {e}")

    elif attack_type == 2:
        try:
            dv_username = input("inserire username: ")
            dv_password = input("inserire password: ")
            dv_voto = input("inserire il voto: ")
            token_idp_falso = os.urandom(64)
            print(f"fake token di accesso generato")
            double_voter = Elettore(f"{dv_username}", f"{dv_password}")
            pk_falsa = double_voter.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            urna.get_tx_vote({
                "chiave_effimera": pk_falsa,
                "token_idp": token_idp_falso,
                "voto": hybrid_encrypt(f"{dv_voto}", pk_commissione) 
            })
        except SecurityError as e:
            print(f"{e}")
        except PermissionError as e:
            print(f"[AUTH ERROR] {e}")

    elif attack_type == 3:
        root_valida = urna.merkle_tree.get_root()
        original_registro_voti = urna.registro_voti[0]
        urna.registro_voti[0] = "HACKED_" + urna.registro_voti[0]
        urna.merkle_tree.leaves = urna.registro_voti
        urna.merkle_tree.build_tree()

        if root_valida != urna.merkle_tree.get_root():
            print(f"Manomissione rilevata! Root cambiata!!")
            print(f"merkle root originale: {root_valida[:10]}")
            print(f"merkle root compromessa: {urna.merkle_tree.get_root()[:10]}")
        urna.registro_voti[0] = original_registro_voti
        urna.merkle_tree.leaves = urna.registro_voti
        urna.merkle_tree.build_tree()

print("\n[5] CHIUSURA ELEZIONI E SCRUTINIO FINALE")

n_frammenti_disp = int(input("quanti membri del consiglio sono disponibili per ricostruire la chiave? "))
segreto_ricostruito = recover_secret(frammenti[:n_frammenti_disp])
if(segreto_scrutinio == segreto_ricostruito):
    print("Chiave di scrutinio ricostruito con successo")
else:
    print("Impossibile ricostruire la chiave di scrutinio\n")
    sys.exit()

sk_commissione_ricostruita = segreto_ricostruito.to_bytes(
16,
'big'
)

sk_bytes_ricostruita = decrypt_private_key(
    sk_commissione_cifrata["ciphertext"],
    sk_commissione_cifrata["iv"],
    sk_commissione_ricostruita
)

sk_commissione = load_der_private_key(
    sk_bytes_ricostruita,
    password=None
)

for i, tx in enumerate(urna.registro_voti):
    voti = json.loads(tx)
    pacchetto = {
        "voto_cifrato": bytes.fromhex(voti["voto_hex"]),
        "chiave_cifrata": bytes.fromhex(voti["chiave_aes_hex"]),
        "iv": bytes.fromhex(voti["iv_hex"])
    }
    voto_chiaro = hybrid_decrypt(pacchetto, sk_commissione)
    candidato = voto_chiaro.split('|')[0]
    if candidato in lista_candidati:
        lista_candidati[candidato] += 1

# da fixare la stampa del vincitore
voto_massimo = max(lista_candidati.values())
vincitore_votazioni = [nome for nome, voti in lista_candidati.items() if voti == voto_massimo]

if len(vincitore_votazioni) == 0:
    print("nessun vincitore! nessun voto valido espresso")
elif len(vincitore_votazioni) == 1:
    print(f"VINCITORE ELEZIONI: {vincitore_votazioni[0]}")
else:
    print(f"PAREGGIO! I VINCITORI SONO: ")
    for vincitore in vincitore_votazioni:
        print(vincitore)