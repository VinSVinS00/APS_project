import hashlib
import secrets
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PRIME = 0xfffffffffffffffffffffffffffffffeffffffffffffffff # numero a 192 bit, PRIME > 2^128

# leaves = lista di voti

class MerkleTree:
    def __init__(self, leaves=None):
        if leaves:
            self.leaves = leaves
        else:
            self.leaves = []
        self.tree = []
        if self.leaves:
            self.build_tree()

    # conversione in binario (encode) -> calcolo del hash puro (SHA256) -> converisone in esadecimale (hexdigest)
    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def build_tree(self):
        if not self.leaves:
            return
        
        current_layer = []
        for tx in self.leaves:
            hash_voto = self._hash(tx)
            current_layer.append(hash_voto)
        self.tree = [current_layer]

        while len(current_layer) > 1:
            next_layer = []
            
            if len(current_layer) % 2 != 0:
                current_layer.append(current_layer[-1])
            
            for i in range(0, len(current_layer), 2):
                combined_hash = self._hash(current_layer[i] + current_layer[i+1])
                next_layer.append(combined_hash)
            
            current_layer = next_layer
            self.tree.append(current_layer)

    def get_root(self) -> str:
        return self.tree[-1][0] if self.tree else ""
    
    # scorre il merkle tree per trovare la ricevuta (proof) del voto dello studente (studente = merkletree[index])
    def get_proof(self, index):
        proof = []
        for layer in self.tree[:-1]:
            if index % 2 == 0:
                sibling_index = index + 1 # elemento successivo = fratello
                if sibling_index >= len(layer): # se stesso = fratello
                    sibling_index = index
            else:
                sibling_index = index - 1 # elemento precedente = fratello
            
            proof.append(layer[sibling_index])
            index = index // 2  # next layer

        return proof
    

    def get_proof(self, index):
        proof = []
        for layer in self.tree[:-1]:
            if index % 2 == 0:
                sibling_index = index + 1 # elemento successivo = fratello
                if sibling_index >= len(layer): # se stesso = fratello
                    sibling_index = index
            else:
                sibling_index = index - 1 # elemento precedente = fratello
            
            proof.append(layer[sibling_index])
            index = index // 2  # next layer

        return proof
    
    
# divisione del segreto in n frammenti, ne servono t per ricostruirlo (SHAMIR)
# geometricamente, è una figura con coefficienti an,a2,a1,a0 ed incognite xn,x2,x1 con a0 = termine noto = segreto
def split_secret(secret_int, t, n):
    if t > n:
        raise ValueError("n deve essere maggiore i t")
    
    # coefficients = lista dei coefficienti a0,a1,a2...
    coefficients = []
    coefficients.append(secret_int) # a0 inserito per primo, è il segreto
    
    for i in range(t - 1):
        coeff_random = secrets.randbelow(PRIME)
        coefficients.append(coeff_random)
        
    coordinates = []
    for ascissa in range(1, n + 1): # ascissa scelta fissa sequenzialmente
        ordinata = 0
        for j in range(len(coefficients)): # ordinata calcolata a partire dall'ascissa, determina anche l'esponente coefficiente
            coeff = coefficients[j]
            termine = (coeff * pow(ascissa, j, PRIME)) % PRIME # aj * x^j % PRIME
            ordinata = (ordinata + termine) % PRIME
            # ogni singola ordinata di una (ascissa,ordinata) è la somma delle ordinate del for interno
            
        coordinates.append((ascissa,ordinata)) # ascissa,ordinata per ogni membro della commissione
        
    return coordinates

# a^-1 mod m, funzione inversa, n --> 1/n
def _mod_inverse(a, m):
    return pow(a, m - 2, m)

# le sole coordinate (ascissa,ordinata) partecipanti allo scrutinio (non per forza tutti i membri n, porebbe anche essere un numero t < n)
# sfrutta l'algoritmo di Langrange per ricostruire il segreto
def recover_secret(coordinates): 
    secret = 0
    k = len(coordinates) 
    
    for i in range(k):
        xi = coordinates[i][0]
        yi = coordinates[i][1]
        
        num = 1
        den = 1
        
        for j in range(k):
            if i != j:
                xj = coordinates[j][0]
                # formula di Lagrange per x=0: (0 - xj) / (xi - xj)
                num = (num * (-xj)) % PRIME
                den = (den * (xi - xj)) % PRIME
                
        real_den = _mod_inverse(den, PRIME) # den --> 1 / den
        lagrange_coeff = (num * real_den) % PRIME # --> num * real_den = num / den
        
        termine_segreto = (yi * lagrange_coeff) % PRIME
        secret = (secret + termine_segreto) % PRIME
        
    return secret


def rsa_key_generation():
    chiave_privata = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048 # bit
    )
    chiave_pubblica = chiave_privata.public_key()
    return chiave_privata, chiave_pubblica


# 1. cifratura del voto (AES-GCM)
# 2. cifratura della chiave AES (RSA-OAEP)
def hybrid_encrypt(voto, rsa_chiave_pubblica):
    if isinstance(voto, str):
        voto_da_cifrare = voto.encode('utf-8')
    else:
        voto_da_cifrare = voto
    
    # 1.
    chiave_aes = AESGCM.generate_key(bit_length=256) # 256 bit
    aes_gcm = AESGCM(chiave_aes)
    
    iv = os.urandom(12) # iv = byte casuali dal SO
    
    voto_cifrato = aes_gcm.encrypt(iv, voto_da_cifrare, None)

    # 2.
    chiave_aes_cifrata = rsa_chiave_pubblica.encrypt(
        chiave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    pacchetto_voto = {
        "voto_cifrato": voto_cifrato,
        "iv": iv,
        "chiave_cifrata": chiave_aes_cifrata,
    }
    return pacchetto_voto

# 1. decifratura della chiave AES usata per cifrare il voto originale
# 2. decifratura del voto finale
def hybrid_decrypt(pacchetto_voto, rsa_chiave_privata):

    voto_cifrato = pacchetto_voto["voto_cifrato"]
    iv = pacchetto_voto["iv"]
    chiave_aes_cifrata = pacchetto_voto["chiave_cifrata"]
    
    # 1.
    chiave_aes = rsa_chiave_privata.decrypt(
        chiave_aes_cifrata,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 2.
    aes_gcm = AESGCM(chiave_aes)
    voto_decifrato = aes_gcm.decrypt(iv, voto_cifrato, None)
    
    return voto_decifrato.decode('utf-8')

def encrypt_private_key(private_key_bytes, aes_key):
    aes = AESGCM(aes_key)
    iv = os.urandom(12)

    # la chiave da cifrare è la sk_commissione, appositamente trasformata in una serie di byte (per AES)
    private_key_encrypted = aes.encrypt(
        iv,
        private_key_bytes,
        None
    )

    return {
        "ciphertext": private_key_encrypted,
        "iv": iv
    }


def decrypt_private_key(ciphertext, iv, aes_key):
    aes = AESGCM(aes_key)

    return aes.decrypt(
        iv,
        ciphertext,
        None
    )