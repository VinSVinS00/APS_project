import json
import secrets
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto import rsa_key_generation, hybrid_encrypt, MerkleTree
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

class IdentityProvider:
    def __init__(self):
        self.chiave_privata, self.chiave_pubblica = rsa_key_generation()
        
        self.database_utenti = {
            "vincenzo_vitolo": "pwdVitolo2000",
            "davide_ruocco": "pwdRuocco2003",
            "paolo_vitale": "pwdVitale2002"
        }
        
        self.already_voted_students = []

    # 1. check delle credenziali
    # 2. check di double voter
    # 3. firma della pk effimera dello studente come Token di accesso al voto con la sk del idp
    def authenticate_and_sign_key(self, username, password, chiave_pubblica_effimera):

        if username not in self.database_utenti or self.database_utenti[username] != password:
            raise PermissionError("Accesso fallita! Username o Password errati")
        
        for utente in self.already_voted_students:
            if utente == username:
                raise ValueError("Accesso rifiutato! Questo studente ha già votato!!")

        idp_token = self.chiave_privata.sign(
            chiave_pubblica_effimera,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        self.already_voted_students.append(username)
        return idp_token


class DigitalUrna:
    def __init__(self, idp_pk):
        self.idp_pk = idp_pk
        self.registro_voti = [] # formato JSON, è il log delle foglie del merkle tree
        self.merkle_tree = MerkleTree()
        self.chiavi_effimere_usate = []

    # 1. convalida del token del idp
    # 2. controllo sul double voting
    # 3. inserimento hash nel Tamper Evident Log del markle tree
    def get_tx_vote(self, transazione):

        # pacchetto voto
        chiave_eff = transazione["chiave_effimera"]
        token_idp = transazione["token_idp"]
        voto = transazione["voto"]

        try:
            self.idp_pk.verify( # verifica che l'idp sia valido e non inventato (Vrfy)
                token_idp,
                chiave_eff,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception:
            raise SecurityError("Errore di Validazione: Il token dell'Identity Provider non è valido!")

        if chiave_eff in self.chiavi_effimere_usate:
            raise SecurityError("Attenzione!! Replay Attack o Double Voting rilevato!!")

        self.chiavi_effimere_usate.append(chiave_eff) # voto accettato

        # voto cifrato: > stringa compatta > esadecimale (.hex)
        tx_compattata = json.dumps({
            "voto_hex": voto["voto_cifrato"].hex(),
            "chiave_aes_hex": voto["chiave_cifrata"].hex()
        })
        
        self.registro_voti.append(tx_compattata)
        
        # update dei voti e della merkle root nel merkle tree
        self.merkle_tree.leaves = self.registro_voti
        self.merkle_tree.build_tree()
        
        # ricevuta di voto che spetta al elettore
        indice_voto = len(self.registro_voti) - 1
        merkle_proof = self.merkle_tree.get_proof(indice_voto)
        ricevuta = {
            "status": "VOTO_ACCETTATO",
            "index": indice_voto,
            "merkle_proof": merkle_proof,
            "merkle_root_corrente": self.merkle_tree.get_root()
        }
        return ricevuta


class Elettore:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.sk_e, self.pk_e = rsa_key_generation()
    
    # 1. autenticazione SSO se le credenziali sono corrette
    # 2. aggiunta del nonce e timestamp al voto
    # 3. invio di tx all'urna digitale (conferma voto)
    def voto(self, candidato_votato, idp, urna, pk_commissione):
        # passiamo pk_e in formato DER, che la trasforma in un array di byte
        pk_e = self.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # 1.
        token_idp = idp.authenticate_and_sign_key(self.username, self.password, pk_e)
        
        # 2.
        nonce = secrets.token_hex(16)
        timestamp = str(int(time.time()))
        msg_timestamp = f"{candidato_votato}|{nonce}|{timestamp}"

        voto_cifrato = hybrid_encrypt(msg_timestamp, pk_commissione)

        # 3.
        transazione_tx = {
            "chiave_effimera": pk_e,
            "token_idp": token_idp,
            "voto": voto_cifrato,
        }
        ricevuta = urna.get_tx_vote(transazione_tx)

        return ricevuta

class SecurityError(Exception):
    pass