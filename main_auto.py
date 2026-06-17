import os
import secrets
import json
from crypto import rsa_key_generation, split_secret, recover_secret, hybrid_encrypt, hybrid_decrypt, encrypt_private_key, decrypt_private_key
from actors import IdentityProvider, DigitalUrna, Elettore, SecurityError
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_der_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



print("SIMULAZIONE SISTEMA DI VOTO ELETTRONICO\n")

print("[1] CONFIGURAZIONE COMMISSIONE")

sk_commissione, pk_commissione = rsa_key_generation()

# sk_commissione --> trasformazione in sequenza di byte (in formato per AES)
sk_bytes = sk_commissione.private_bytes(
    Encoding.DER,
    PrivateFormat.PKCS8,
    NoEncryption()
)

# chiave casuale generata (AES), serve per cifrare sk_commissione (attualmente sk_bytes)
chiave_scrutinio = AESGCM.generate_key(bit_length=128)

# cifratura della sk_commissione
sk_commissione_cifrata = encrypt_private_key(
    sk_bytes,
    chiave_scrutinio
)

# sk_comissione --> trasformazione in int (in formato per SHAMIR)
segreto_scrutinio = int.from_bytes(
    chiave_scrutinio,
    'big'
)

n_membri = 5
t_membri_necessari = 3

frammenti = split_secret(
    segreto_scrutinio,
    t=t_membri_necessari,
    n=n_membri
)

# sk_commissione eliminata
sk_commissione = None
print(f"Chiave di scrutinio divisa in {n_membri} parti con successo, {t_membri_necessari}/{n_membri} parti sufficienti per la ricostruzione\n")

print("[2] INIZIALIZZAZIONE SERVER")
idp = IdentityProvider()
urna = DigitalUrna(idp_pk=idp.chiave_pubblica) #l'urna prende in input la chiave publica del idp
print("Identity Provider e Urna correttamente attivi!\n")

print("[3] APERTURA SEGGIO")
studenti = [
    ("vincenzo_vitolo", "vv", "Terranova"),
    ("davide_ruocco", "dr", "Cupo"),
    ("paolo_vitale", "pv", "Terranova")
]

for user, password, voto in studenti:
    print(f"\nLo studente '{user}' esprime il voto...")
    client = Elettore(user, password)
    ricevuta = client.voto(voto, idp, urna, pk_commissione)
    # controllo sul voto per accettare la scheda elettorale, ad esempio che sia nella lista dei candidati o che sia semanticamente corretto
    print(f"Voto accettato! Indice: {ricevuta['index']}, merkle root: {ricevuta['merkle_root_corrente'][:10]}")

print("\n[4] FASE DI ATTACCO AL SISTEMA")

print("\nVincenzo prova a rivotare (double-voting)...")
try:
    Elettore("vincenzo_vitolo", "vv").voto("Terranova", idp, urna, pk_commissione)
except ValueError as e:
    print(f"{e}")

print("\nVotazione con Token idp falso...")
try:
    double_voter = Elettore("paolo_vitale", "pv")
    pk_falsa = double_voter.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    
    voto_cifrato = hybrid_encrypt("Terranova", pk_commissione)
    voto_json_str = json.dumps({
        "voto_hex": voto_cifrato["voto_cifrato"].hex(),
        "chiave_aes_hex": voto_cifrato["chiave_cifrata"].hex(),
        "iv_hex": voto_cifrato["iv"].hex()
    })
    
    urna.get_tx_vote({
        "voto_json_str": voto_json_str,
        "chiave_effimera": pk_falsa,
        "token_idp": b"firma_falsa",
        "sigma_elettore": os.urandom(256) 
    })
except SecurityError as e:
    print(f"Attacco correttamente bloccato: {e}")

print("\nIntercettazione Man-in-the-Middle...")
try:
    man_in_the_middle = Elettore("davide_ruocco", "dr")
    pk_e = man_in_the_middle.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    
    token_idp = idp.authenticate_and_sign_key("davide_ruocco", "dr", pk_e)
    voto_cifrato_legittimo = hybrid_encrypt("Cupo", pk_commissione)
    
    # pacchetto voto
    transazione_intercettata = {
        "chiave_effimera": pk_e,
        "token_idp": token_idp,
        "voto": voto_cifrato_legittimo
    }

    voto_manomesso= hybrid_encrypt("Terranova", pk_commissione)
    transazione_intercettata["voto"] = voto_manomesso
    
    urna.get_tx_vote(transazione_intercettata)
    print("Il sistema ha fallito!! L'Urna ha accettato una transazione modificata in transito!")
except (SecurityError, Exception) as e:
    print(f"Intercettazione bloccata!! La transazione alterata viola i vincoli crittografici")

print("\nManomissione DB (Gestore Malevolo)...")
if len(urna.registro_voti) > 0:
    root_valida = urna.merkle_tree.get_root()
    originale = urna.registro_voti[0]["voto_json_str"]
    
    urna.registro_voti[0]["voto_json_str"] = originale.replace("voto_hex", "hacker")
    
    urna.merkle_tree.leaves = [json.dumps(tx) for tx in urna.registro_voti]
    urna.merkle_tree.build_tree()

    if root_valida != urna.merkle_tree.get_root():
        print(f"Manomissione rilevata! Root cambiata!!")
        print(f"Root originale: {root_valida[:10]}")
        print(f"Root attuale: {urna.merkle_tree.get_root()[:10]}")
    
    urna.registro_voti[0]["voto_json_str"] = originale
    urna.merkle_tree.leaves = [json.dumps(tx) for tx in urna.registro_voti]
    urna.merkle_tree.build_tree()
else:
    print("Nessun voto nel registro!")

print("\n[5] CHIUSURA ELEZIONI E SCRUTINIO FINALE")

segreto_ricostruito = recover_secret(frammenti[:3])

if(segreto_scrutinio == segreto_ricostruito):
    print("Chiave di scrutinio ricostruito con successo")
else:
    print("Impossibile ricostruire la chiave di scrutinio\n")

# int --> byte
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

print("\ntutte le votazioni:")
for i, tx in enumerate(urna.registro_voti):
    pacchetto_json_str = tx["voto_json_str"]
    voti = json.loads(pacchetto_json_str)
    
    pacchetto = {
        "voto_cifrato": bytes.fromhex(voti["voto_hex"]),
        "chiave_cifrata": bytes.fromhex(voti["chiave_aes_hex"]),
        "iv": bytes.fromhex(voti["iv_hex"])
    }
    voto_chiaro = hybrid_decrypt(pacchetto, sk_commissione)
    candidato = voto_chiaro.split('|')[0]
    print(f"voto {i} - {candidato}")