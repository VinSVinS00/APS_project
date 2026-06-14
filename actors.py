import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from crypto import rsa_key_generation, hybrid_encrypt, MerkleTree

class IdentityProvider:
    def __init__(self):
        self.chiave_privata, self.chiave_pubblica = rsa_key_generation()
        
        #db simulato
        self.database_utenti = {
            "vincenzo_vitolo": "pwdVitolo2000",
            "davide_ruocco": "pwdRuocco2003",
            "nome_cognome": "password1234"
        }
        
        self.already_voted_students = []

    # 1. check delle credenziali
    # 2. check di double voter
    # 3. firma della pk effimera dello studente come Token di accesso al voto
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
    def __init__(self, idp_chiave_pubblica):
        self.idp_chiave_pubblica = idp_chiave_pubblica
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
            self.idp_chiave_pubblica.verify(
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
        
        # update del merkle tree
        self.merkle_tree.leaves = self.registro_voti
        self.merkle_tree.build_tree()
        
        indice_voto = len(self.registro_voti) - 1
        merkle_proof = self.merkle_tree.get_proof(indice_voto)
        
        # ricevuta di voto che spetta al elettore
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
        self.pk_e, self.sk_e = rsa_key_generation() # chiavi effimere per la sessione di voto
    
    def voto(self, id_candidato, idp_instance, urna_instance, pk_commissione):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pk_e_bytes = self.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        token_idp = idp_instance.authenticate_and_sign_key(self.username, self.password, pk_e_bytes)
        nonce = secrets.token_hex(16)
        timestamp = str(int(time.time()))
        messaggio = f"{id_candidato}|{nonce}|{timestamp}".encode()

        voto_cifrato = hybrid_encrypt(messaggio, pk_commissione)

        transazione_tx = {
            "chiave_effimera": pk_e_bytes,
            "token_idp": token_idp,
            "voto": voto_cifrato,
        }

        ricevuta = urna_instance.get_tx_vote(transazione_tx)
        return ricevuta

class SecurityError(Exception):
    pass