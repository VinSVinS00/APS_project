import json
import statistics
import time
from dataclasses import dataclass
from typing import List
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_der_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
import secrets as _secrets

from crypto import (
    rsa_key_generation, split_secret, recover_secret,
    hybrid_encrypt, hybrid_decrypt,
    encrypt_private_key, decrypt_private_key,
)
from actors import IdentityProvider, DigitalUrna, Elettore


def now_ns() -> int:
    return time.perf_counter_ns()

def elapsed_ms(t0: int) -> float:
    return (now_ns() - t0) / 1e6


@dataclass
class VoteMetric:
    auth_idp_ms: float
    hybrid_encrypt_ms: float
    client_sign_ms: float
    urna_validation_and_append_ms: float
    merkle_proof_ms: float
    voto_totale_ms: float
    tx_pk_effimera_bytes: int
    tx_token_idp_bytes: int
    tx_voto_bytes: int
    tx_totale_bytes: int
    merkle_proof_len: int


@dataclass
class ScrutinioMetric:
    shamir_recover_ms: float
    decrypt_sk_commissione_ms: float
    hybrid_decrypt_per_voto_ms: float
    decrypt_totale_ms: float
    scrutinio_totale_ms: float


def setup(N: int):
    sk_comm, pk_comm = rsa_key_generation()

    sk_bytes = sk_comm.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    chiave_scrutinio = AESGCM.generate_key(bit_length=128)
    sk_comm_cifrata = encrypt_private_key(sk_bytes, chiave_scrutinio)

    segreto = int.from_bytes(chiave_scrutinio, "big")
    frammenti = split_secret(segreto, t=3, n=5)

    sk_comm = None  

    idp = IdentityProvider()
    urna = DigitalUrna(idp.chiave_pubblica)

    for i in range(N):
        idp.database_utenti[f"studente_bench_{i}"] = f"pwd{i}"

    return {
        "pk_commissione": pk_comm,
        "sk_commissione_cifrata": sk_comm_cifrata,
        "frammenti": frammenti,
        "segreto_scrutinio": segreto,
        "idp": idp,
        "urna": urna,
    }


def benchmark_voto(N: int, ctx) -> List[VoteMetric]:
    idp, urna, pk_comm = ctx["idp"], ctx["urna"], ctx["pk_commissione"]
    candidati = ["Terranova", "Cupo", "Altro"]
    metrics: List[VoteMetric] = []

    for i in range(N):
        username = f"studente_bench_{i}"
        password = f"pwd{i}"
        
        elettore = Elettore(username, password)
        pk_e_der = elettore.pk_e.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        t = now_ns()
        token_idp = idp.authenticate_and_sign_key(username, password, pk_e_der)
        t_auth = elapsed_ms(t)

        candidato = candidati[i % len(candidati)]
        voto_sicuro = f"{candidato}|{_secrets.token_hex(16)}|{int(time.time())}"

        t = now_ns()
        voto_cifrato = hybrid_encrypt(voto_sicuro, pk_comm)
        t_enc = elapsed_ms(t)

        voto_str = json.dumps({
            "voto_hex": voto_cifrato["voto_cifrato"].hex(),
            "chiave_aes_hex": voto_cifrato["chiave_cifrata"].hex(),
            "iv_hex": voto_cifrato["iv"].hex(),
        })

        t = now_ns()
        firma_elettore = elettore.sk_e.sign(
            voto_str.encode("utf-8"),
            asym_padding.PKCS1v15(),
            crypto_hashes.SHA256()
        )
        t_client_sign = elapsed_ms(t)

        tx_voto_len = len(voto_str.encode("utf-8")) + len(firma_elettore)
        tx_pk_len = len(pk_e_der)
        tx_token_len = len(token_idp)
        tx_tot_len = tx_pk_len + tx_token_len + tx_voto_len

        tx_payload = {
            "voto_json_str": voto_str,
            "chiave_effimera": pk_e_der,
            "token_idp": token_idp,
            "sigma_elettore": firma_elettore
        }
        t = now_ns()
        ricevuta = urna.get_tx_vote(tx_payload)
        t_urna_processing = elapsed_ms(t)

        t = now_ns()
        idx_corrente = len(urna.registro_voti) - 1
        proof = urna.merkle_tree.get_proof(idx_corrente)
        t_proof = elapsed_ms(t)

        metrics.append(VoteMetric(
            auth_idp_ms=t_auth,
            hybrid_encrypt_ms=t_enc,
            client_sign_ms=t_client_sign,
            urna_validation_and_append_ms=t_urna_processing,
            merkle_proof_ms=t_proof,
            voto_totale_ms=t_auth + t_enc + t_client_sign + t_urna_processing + t_proof,
            tx_pk_effimera_bytes=tx_pk_len,
            tx_token_idp_bytes=tx_token_len,
            tx_voto_bytes=tx_voto_len,
            tx_totale_bytes=tx_tot_len,
            merkle_proof_len=len(proof) if proof else 0,
        ))

    return metrics


def benchmark_scrutinio(ctx, N: int) -> ScrutinioMetric:
    frammenti, segreto = ctx["frammenti"], ctx["segreto_scrutinio"]
    sk_cifrata, urna = ctx["sk_commissione_cifrata"], ctx["urna"]

    t = now_ns()
    segreto_ricostruito = recover_secret(frammenti[:3])
    t_shamir = elapsed_ms(t)
    assert segreto_ricostruito == segreto, "Errore fatale: Shamir recovery fallita"

    sk_comm_bytes = segreto_ricostruito.to_bytes(16, "big")
    t = now_ns()
    sk_bytes_ric = decrypt_private_key(sk_cifrata["ciphertext"], sk_cifrata["iv"], sk_comm_bytes)
    t_dec_sk = elapsed_ms(t)
    sk_comm = load_der_private_key(sk_bytes_ric, password=None)

    t_per_voto = []
    for tx_dict in urna.registro_voti:
        v = json.loads(tx_dict["voto_json_str"])
        pacchetto = {
            "voto_cifrato": bytes.fromhex(v["voto_hex"]),
            "chiave_cifrata": bytes.fromhex(v["chiave_aes_hex"]),
            "iv": bytes.fromhex(v["iv_hex"]),
        }
        t = now_ns()
        hybrid_decrypt(pacchetto, sk_comm)
        t_per_voto.append(elapsed_ms(t))

    t_dec_tot = sum(t_per_voto)

    return ScrutinioMetric(
        shamir_recover_ms=t_shamir,
        decrypt_sk_commissione_ms=t_dec_sk,
        hybrid_decrypt_per_voto_ms=statistics.mean(t_per_voto) if t_per_voto else 0.0,
        decrypt_totale_ms=t_dec_tot,
        scrutinio_totale_ms=t_shamir + t_dec_sk + t_dec_tot,
    )


def print_report(N, reps, all_vote, avg_scrut, t_setup):
    def stats(label, values, unit="ms"):
        avg = statistics.mean(values) if values else 0.0
        p50 = statistics.median(values) if values else 0.0
        p95 = (statistics.quantiles(values, n=20)[-1] if len(values) >= 20 else (max(values) if values else 0.0))
        print(f"  {label}_avg = {avg:.3f} {unit}")
        print(f"  {label}_p50 = {p50:.3f} {unit}")
        print(f"  {label}_p95 = {p95:.3f} {unit}")

    print(f"   REPORT DI BENCHMARK PRESTAZIONALE (N={round(N)})")
    print(f"Setup iniziale medio: {t_setup:.2f} ms")
    print("\n[FASE DI VOTO INDIVIDUALE]")
    stats("Autenticazione OIDC (IdP)",       [v.auth_idp_ms for v in all_vote])
    stats("Cifratura Ibrida Elettore",       [v.hybrid_encrypt_ms for v in all_vote])
    stats("Generazione Firma Elettore",      [v.client_sign_ms for v in all_vote])
    stats("Validazione Urna & Merkle Append",[v.urna_validation_and_append_ms for v in all_vote])
    stats("Estrazione Merkle Proof",         [v.merkle_proof_ms for v in all_vote])
    stats("Latenza Totale Processo Voto",    [v.voto_totale_ms for v in all_vote])
    
    tot_s = sum(v.voto_totale_ms for v in all_vote) / 1000.0
    print(f"  -> THROUGHPUT COMPLESSIVO: {len(all_vote) / tot_s:.1f} voti/secondo")

    print("\n[DIMENSIONE OCCUPAZIONE DI MEMORIA / RETE]")
    print(f"  Chiave Pubblica Effimera: {statistics.mean([v.tx_pk_effimera_bytes for v in all_vote]):.0f} B")
    print(f"  Token Token OIDC IdP:     {statistics.mean([v.tx_token_idp_bytes for v in all_vote]):.0f} B")
    print(f"  Payload Voto Cifrato:     {statistics.mean([v.tx_voto_bytes for v in all_vote]):.0f} B")
    tx_avg = statistics.mean([v.tx_totale_bytes for v in all_vote])
    print(f"  Dimensione Transazione TX: {tx_avg:.0f} B ({tx_avg/1024:.2f} KiB)")
    print(f"  Dimensione Merkle Proof:   {statistics.mean([v.merkle_proof_len for v in all_vote]):.2f} elementi foglia")

    print("\n[FASE DI SCRUTINIO MASSIVO]")
    print(f"  Ricostruzione Lagrange Shamir:       {avg_scrut['shamir_recover']:.3f} ms")
    print(f"  Decifratura (Unwrapping) Chiave RSA: {avg_scrut['decrypt_sk']:.3f} ms")
    print(f"  Tempo di Decifratura medio per Voto: {avg_scrut['decrypt_per_voto']:.3f} ms")
    print(f"  Tempo di Decifratura Totale Registro: {avg_scrut['decrypt_totale']:.2f} ms")
    print(f"  Latenza Scrutinio Totale (Quorum):   {avg_scrut['scrutinio_totale']:.2f} ms")
    print(f"  THROUGHPUT SCRUTINIO: {N / (avg_scrut['scrutinio_totale']/1000.0):.1f} voti scrutinati/s")
    print("="*50)


N_VOTANTI = 100
REPS = 3

all_vote: List[VoteMetric] = []
scrut_runs: List[ScrutinioMetric] = []
t_setup_accumulato = 0.0

for r in range(REPS):
    print(f"[Run {r+1}/{REPS}] Inizializzazione ambiente ed entità elettorali")
    t = now_ns()
    ctx = setup(N_VOTANTI)
    t_setup_accumulato += elapsed_ms(t)

    print(f"[Run {r+1}/{REPS}] Simulazione afflusso alle urne ({N_VOTANTI} studenti)")
    all_vote.extend(benchmark_voto(N_VOTANTI, ctx))

    print(f"[Run {r+1}/{REPS}] Chiusura elezione e avvio dello scrutinio commissione")
    scrut_runs.append(benchmark_scrutinio(ctx, N_VOTANTI))

avg_scrutinio_dict = {
    "shamir_recover": statistics.mean([s.shamir_recover_ms for s in scrut_runs]),
    "decrypt_sk": statistics.mean([s.decrypt_sk_commissione_ms for s in scrut_runs]),
    "decrypt_per_voto": statistics.mean([s.hybrid_decrypt_per_voto_ms for s in scrut_runs]),
    "decrypt_totale": statistics.mean([s.decrypt_totale_ms for s in scrut_runs]),
    "scrutinio_totale": statistics.mean([s.scrutinio_totale_ms for s in scrut_runs])
}

t_setup_medio = t_setup_accumulato / REPS
print_report(N_VOTANTI, REPS, all_vote, avg_scrutinio_dict, t_setup_medio)
