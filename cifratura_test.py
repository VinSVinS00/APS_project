from crypto import rsa_key_generation, hybrid_encrypt, hybrid_decrypt

print("Commissione genera la coppia di chiavi sk&pk")
chiave_privata_comm, chiave_pubblica_comm = rsa_key_generation()
print(f"pk: {chiave_pubblica_comm}\nsk: {chiave_privata_comm}")

voto_originale = "Terranova"
print(f"Vitolo vota: '{voto_originale}'")

print("Cifratura...")
pacchetto_voto = hybrid_encrypt(voto_originale, chiave_pubblica_comm)

# questo lo vedrà un attaccante che intercetta la rete (nessun altro potrebbe vedere la transizione TX)
print(f"Chiave AES cifrata con RSA: {pacchetto_voto['chiave_cifrata'][:20]}...")
print(f"Vettore di Inizializzazione (IV): {pacchetto_voto['iv'].hex()}")
print(f"Voto cifrato con AES: {pacchetto_voto['voto_cifrato'].hex()[:40]}...")

print("\nUrne chiuse! Inizio decifratura del pacchetto...")
try:
    voto_decifrato = hybrid_decrypt(pacchetto_voto, chiave_privata_comm)
    print(f"Voto decifrato con successo: '{voto_decifrato}'")
    
    print(f"\nvoto effettivo iniziale: {voto_originale}")
    print(f"voto decifrato: {voto_decifrato}")
except Exception as e:
    print(f"Errore critico durante la decifratura: {e}")