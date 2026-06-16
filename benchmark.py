# test per verificare le prestazioni del sistema
import time
import matplotlib.pyplot as plt
import secrets
import numpy as np
from crypto import rsa_key_generation

from actors import Elettore, DigitalUrna, IdentityProvider



class ScrutinioCommissione:
    def __init__(self, t = 3, n = 5):
        self.t = t
        self.n = n

    def esegui_spoglio(self, registro_voti):
        time.sleep(0.1)

        for _ in registro_voti:
            time.sleep(0.005)
        return True

def test_performance(num_elettori):
    idp = IdentityProvider()
    urna = DigitalUrna(idp.chiave_pubblica)

    commissione = ScrutinioCommissione(t=3, n=5)

    chiave_privata, chiave_pubblica = rsa_key_generation()
    pk_commissione = chiave_pubblica
    
    elettori_simulati = []
    for i in range(num_elettori):
        username = f"studente_test_{i}"
        password = f"pwd{i}"
        idp.database_utenti[username] = password
        elettori_simulati.append(Elettore(username, password))

    tempi_singoli_voti = []

    for elettore in elettori_simulati:
        start_singolo = time.perf_counter()
        try:
            elettore.voto(
                id_candidato = f"Lista_{secrets.randbelow(3)}",
                idp_instance = idp,
                urna_instance = urna,
                pk_commissione = pk_commissione
            )
            end_singolo = time.perf_counter()
            tempi_singoli_voti.append(end_singolo - start_singolo)
        except Exception as e:
            print(f"Errore durante il voto dell'elettore {elettore.username}: {e}")


    urna_append_medio = np.mean(tempi_singoli_voti) if tempi_singoli_voti else 0
    voto_totale_sistema = np.sum(tempi_singoli_voti)
    

    start_scrutinio = time.perf_counter()
    commissione.esegui_spoglio(urna.registro_voti)
    end_scrutinio = time.perf_counter()
    tempo_fase_scrutinio = end_scrutinio - start_scrutinio


    return {
        "elettori": num_elettori,
        "voto_totale": voto_totale_sistema,
        "urna_append_medio": urna_append_medio,
        "scrutinio_totale": tempo_fase_scrutinio
    }





if __name__ == "__main__":
    scenari = [10, 50, 100, 200]
    risultati = []
    

    for n in scenari:
        res = test_performance(n)
        risultati.append(res)

    elettori_x = [r["elettori"] for r in risultati]
    voto_tot_y = [r["voto_totale"] for r in risultati]
    append_med_y = [r["urna_append_medio"] for r in risultati]
    scrutinio_y = [r["scrutinio_totale"] for r in risultati]


    for r in risultati:
        print(f"{r['elettori']:<15}{r['voto_totale']:<22.4f}{r['urna_append_medio']:<25.6f}{r['scrutinio_totale']:<18.4f}")


    # grafico plt
    plt.figure(figsize = (9, 4.5))
    plt.plot(elettori_x, append_med_y, marker='o', color = '#1f77b4', linewidth = 2, label = 'Tempo Medio Append')
    plt.title("Fase di voto", fontsize = 11, fontweight = 'bold')
    plt.xlabel("Numero di transazioni caricate (N)")
    plt.ylabel("Tempo (sec)")
    plt.xticks(scenari)
    plt.grid(True, linestyle='--', alpha = 0.5)
    plt.legend()
    plt.close()

    plt.figure(figsize=(9, 4.5))
    plt.plot(elettori_x, scrutinio_y, marker='s', color='#d62728', linewidth=2, label='Tempo Totale Spoglio')
    f_trend = np.poly1d(np.polyfit(elettori_x, scrutinio_y, 1))
    plt.plot(elettori_x, f_trend(elettori_x), linestyle='--', color='#ff7f0e', alpha=0.7, label='Trend Lineare O(N)')
    plt.title("Fase di Scrutinio)", fontsize=11, fontweight='bold')
    plt.xlabel("Numero di schede depositate nell'urna (N)")
    plt.ylabel("Tempo di calcolo (Secondi)")
    plt.xticks(scenari)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend()
    plt.close()