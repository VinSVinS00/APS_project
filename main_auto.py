import secrets
import json
from crypto import rsa_key_generation, split_secret, recover_secret, hybrid_encrypt, hybrid_decrypt
from actors import IdentityProvider, DigitalUrna, Elettore, SecurityError
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def main():
    print("SIMULAZIONE SISTEMA DI VOTO ELETTRONICO\n")

    print("[1] CONFIGURAZIONE COMMISSIONE")

    sk_commissione, pk_commissione = rsa_key_generation() # sk nascosta, pk utile per validare le votazioni degli studenti
    
    segreto_scrutinio = secrets.randbelow(2**128) # la chiave di scrutinio, verrà frammentato in n parti (n = membri della commissione)
    n_membri = 5
    t_membri_necessari = 3
    print(f"Divisione della key in n={n_membri} parti ({t_membri_necessari}/{n_membri} parti necessarie e sufficienti per ricostruirla)...")

    frammenti = split_secret(segreto_scrutinio, t=t_membri_necessari, n=n_membri)
    print(f"Chiave di scrutinio divisa in {n_membri} parti con successo\n")

    print("[2] INIZIALIZZAZIONE SERVER")
    idp = IdentityProvider()
    urna = DigitalUrna(idp_pk=idp.chiave_pubblica) #l'urna prende in input la chiave publica del idp
    print("Identity Provider e Urna correttamente attivi!\n")

    print("[3] APERTURA SEGGIO")
    studenti = [
        ("vincenzo_vitolo", "pwdVitolo2000", "Terranova"),
        ("davide_ruocco", "pwdRuocco2003", "Cupo"),
        ("paolo_vitale", "pwdVitale2002", "Terranova")
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
        Elettore("vincenzo_vitolo", "pwdVitolo2000").voto("Terranova", idp, urna, pk_commissione)
    except ValueError as e:
        print(f"{e}")

    print("\nVotazione con Token idp falso...")
    try:
        double_voter = Elettore("paolo_vitale", "pwdVitale2002")
        pk_falsa = double_voter.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        urna.get_tx_vote({ # per generare un token fasullo
            "chiave_effimera": pk_falsa,
            "token_idp": b"firma_falsa",
            "voto": hybrid_encrypt("Terranova", pk_commissione) 
        })
    except SecurityError as e:
        print(f"{e}")

    print("\nIntercettazione Man-in-the-Middle...")
    try:
        man_in_the_middle = Elettore("davide_ruocco", "pwdRuocco2003")
        pk_e = man_in_the_middle.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        
        token_idp = idp.authenticate_and_sign_key("davide_ruocco", "pwdRuocco2003", pk_e)
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
    root_valida = urna.merkle_tree.get_root()
    urna.registro_voti[0] = urna.registro_voti[0].replace("voto_hex", "hacker")
    urna.merkle_tree.leaves = urna.registro_voti
    urna.merkle_tree.build_tree()

    if root_valida != urna.merkle_tree.get_root():
        print(f"Manomissione rilevata! Root cambiata!!")
        print(f"merkle root originale: {root_valida[:10]}")
        print(f"merkle root attuale: {urna.merkle_tree.get_root()[:10]}")
    urna.registro_voti[0] = urna.registro_voti[0].replace("hacker", "voto_hex")
    urna.merkle_tree.build_tree()

    print("\n[5] CHIUSURA ELEZIONI E SCRUTINIO FINALE")
    
    segreto_ricostruito = recover_secret(frammenti[:3])
    if(segreto_scrutinio == segreto_ricostruito):
        print("Chiave di scrutinio ricostruito con successo")
    else:
        print("Impossibile ricostruire la chiave di scrutinio\n")

    print("tutte le votazioni:")
    for i, tx in enumerate(urna.registro_voti):
        voti = json.loads(tx)
        pacchetto = {
            "voto_cifrato": bytes.fromhex(voti["voto_hex"]),
            "chiave_cifrata": bytes.fromhex(voti["chiave_aes_hex"]),
            "iv": bytes.fromhex(voti["iv_hex"])
        }
        voto_chiaro = hybrid_decrypt(pacchetto, sk_commissione)
        candidato = voto_chiaro.split('|')[0]
        print(f"voto {i} - {candidato}")
    
    
if __name__ == "__main__":
    main()