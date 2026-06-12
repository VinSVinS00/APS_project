from crypto import MerkleTree

voti_simulati = ["1", "2", "1", "3"]

albero = MerkleTree(voti_simulati)
root_iniziale = albero.get_root()

print(f"Merkle Root iniziale: {root_iniziale}")

# attacco
voti_simulati[1] = "3"
albero_manomesso = MerkleTree(voti_simulati)
root_manomessa = albero_manomesso.get_root()

print(f"Merkle Root post attacco: {root_manomessa}")

if(root_iniziale != root_manomessa):
    print("sistema attaccato e modificato")
else:
    print("sistema invariato ed integro")