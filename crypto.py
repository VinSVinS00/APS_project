import hashlib

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