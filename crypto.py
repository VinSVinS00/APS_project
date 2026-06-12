import hashlib
import secrets

PRIME = 2**127 - 1

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

# a^-1 mod m
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