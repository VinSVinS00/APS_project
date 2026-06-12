from crypto import split_secret, recover_secret

print("TEST SHAMIR'S SECRET SHARING")

chiave_privata_commissione = 1234567890123456789034567890
print("chiave originale: 1234567890123456789034567890")

# (t=3, n=5)
frammenti = split_secret(chiave_privata_commissione, t=3, n=5)
print(f"Chiave frammentata in {len(frammenti)} parti")
print("\n3/5 membri necessari per la ricostruzione della chiave\n")

for f in frammenti:
    print(f"Membro X: {f[0]}: Y = {str(f[1])[:15]}")

print("\n2/5 membri provano a ricostruire la chiave...")
try:
    chiave_fallita = recover_secret(frammenti[:2])
    print(f"Chiave ricostruita con 2 membri: {chiave_fallita}")
    print(f"Coincide con l'originale? {chiave_fallita == chiave_privata_commissione}")
except Exception as e:
    print(f"Bloccato correttamente o fallito: {e}")

print("\n3/5 membri provano a riscostruire la chiave...")
chiave_ricostruita = recover_secret(frammenti[:3])
print(f"Chiave ricostruita con 3 membri: {chiave_ricostruita}")
print(f"Coincide con l'originale? {chiave_ricostruita == chiave_privata_commissione}")