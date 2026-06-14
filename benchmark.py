# test per verificare le prestazioni del sistema
import time
import matplotlib.pyplot as plt
import secrets
import json


try:
    from actors import Elettore, Urna, IdentityProvider
except ImportError:
    pass


class ScrutinioCommissione:
    def __init__(self, t = 3, n = 5):
        self.t = t
        self.n = n

    def esegui spoglio(self, registro_voti):
        time.sleep(0.1)

        for _ in registro_voti:
            time.sleep(0.01)
        return True

def test_performance(num_elettori):
    idp = IdentityProvider()
    urna = Urna(idp)

    commissione = ScrutinioCommissione(t=3, n=5)
    
    elettori_simulati = [
        Elettore(username = f"user{i}", password = f"pass{i}") 
        for i in range(num_elettori)
    ]

    start_voto = time.perf_counter()

    for elettore in elettori_simulati:
        try:
            elettore.voto(
                id_candidato = f"Lista_{secrets.randbelow(3)}",
                idp_instance = idp,
                urna_instance = urna,
                pk_commissione = pk_commissione
            )
        except Exception as e:
            print(f"Errore durante il voto dell'elettore {elettore.username}: {e}")

    end_voto = time.perf_counter()
    tempo_fase_voto = end_voto - start_voto




    start_urna = time.perf_counter()

    urna.merkle_tree.build_tree()
    end_urna = time.perf_counter()

    tempo_fase_urna = end_urna - start_urna
    tempo_medio_append_urna = tempo_fase_urna / num_elettori


    

    start_scrutinio = time.perf_counter()
    commissione.esegui_spoglio(urna.registro_voti)
    end_scrutinio = time.perf_counter()
    tempo_fase_scrutinio = end_scrutinio - start_scrutinio


    return {
        "elettori": num_elettori,
        "tempo_medio_client": (tempo_fase_voto - tempo_fase_urna) / num_elettori,
        "urna_append_totale": tempo_fase_urna,
        "urna_append_medio": tempo_medio_append_urna,
        "scrutinio_totale": tempo_fase_scrutinio
    }
