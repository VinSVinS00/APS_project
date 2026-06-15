import secrets
from crypto import rsa_key_generation, split_secret, recover_secret, hybrid_encrypt
from actors import IdentityProvider, DigitalUrna, Elettore, SecurityError
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def main():
    print("SIMULAZIONE SISTEMA DI VOTO ELETTRONICO\n")

    print("[1] CONFIGURAZIONE COMMISSIONE")

    _, pk_commissione = rsa_key_generation() # sk nascosta, pk utile per validare le votazioni degli studenti
    
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

    for user, pwd, voto in studenti:
        print(f"\nLo studente '{user}' esprime il voto...")
        client = Elettore(user, pwd)
        ricevuta = client.voto(voto, idp, urna, pk_commissione)
        print(f"Voto accettato! Indice: {ricevuta['index']}, merkle root: {ricevuta['merkle_root_corrente'][:10]}")

    print("\n[4] FASE DI ATTACCO AL SISTEMA)")

    print("\nVincenzo prova a rivotare (double-voting)...")
    try:
        Elettore("vincenzo_vitolo", "pwdVitolo2000").voto("Terranova", idp, urna, pk_commissione)
    except ValueError as e:
        print(f"{e}")

    print("\nVotazione con Token idp falso...")
    try:
        studente_finto = Elettore("paolo_vitale", "pwdVitale2002")
        pk_falsa = studente_finto.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        urna.get_tx_vote({
            "chiave_effimera": pk_falsa,
            "token_idp": b"firma_falsa",
            "voto": hybrid_encrypt("Terranova", pk_commissione)
        })
    except SecurityError as e:
        print(f"{e}")

    print("\nManomissione DB (Gestore Malevolo)...")
    root_valida = urna.merkle_tree.get_root()
    urna.registro_voti[0] = urna.registro_voti[0].replace("voto_hex", "hacker")
    urna.merkle_tree.leaves = urna.registro_voti
    urna.merkle_tree.build_tree()
    if root_valida != urna.merkle_tree.get_root():
        print(f"Manomissione rilevata! Root cambiata: {urna.merkle_tree.get_root()[:10]}...")
    urna.registro_voti[0] = urna.registro_voti[0].replace("hacker", "voto_hex")
    urna.merkle_tree.build_tree()

    print("\n[5] CHIUSURA ELEZIONI E SCRUTINIO FINALE")
    
    segreto_ricostruito = recover_secret(frammenti[:3])
    print(f"Numero di parti sufficiente per la ricostruzione! Segreto: {segreto_ricostruito == segreto_scrutinio}")

if __name__ == "__main__":
    main()