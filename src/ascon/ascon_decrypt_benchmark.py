import sys
import ctypes
import time
import csv
import os
import gc
import psutil

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Cara Penggunaan: python3 ascon_decrypt_benchmark.py <nama_file.enc> [jumlah_trials]")
    sys.exit(1)

INPUT_FILE   = sys.argv[1]
TRIALS       = int(sys.argv[2]) if len(sys.argv) == 3 else 1000
WARMUP       = 50
KEY          = b'PolibatamRKS2026'
METRICS_FILE = INPUT_FILE + '_decrypt_metrics.csv'

try:
    ascon_lib = ctypes.CDLL('./libascon_core.so')
    ascon_lib.decrypt_ascon128.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
    ]
    ascon_lib.decrypt_ascon128.restype = ctypes.c_int
except OSError:
    print("Error: libascon_core.so tidak ditemukan.")
    sys.exit(1)

def run_decryption_test():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: '{INPUT_FILE}' tidak ditemukan.")
        sys.exit(1)

    with open(INPUT_FILE, 'rb') as f:
        raw_payload = f.read()

    # Format file .enc: nonce(16) + ciphertext + tag(16)
    nonce       = raw_payload[:16]
    ciphertext  = raw_payload[16:-16]
    tag         = raw_payload[-16:]
    DATA_SIZE   = len(ciphertext)

    c_nonce     = ctypes.create_string_buffer(nonce)
    c_cipher    = ctypes.create_string_buffer(ciphertext)
    c_tag       = ctypes.create_string_buffer(tag)
    c_decrypted = ctypes.create_string_buffer(DATA_SIZE)

    process = psutil.Process(os.getpid())
    results = []

    print(f"Memuat '{INPUT_FILE}' ({DATA_SIZE} bytes ciphertext).")
    print(f"Memulai {TRIALS} Percobaan Dekripsi Eksklusif...")

    # --- MULAI TIMING TOTAL ---
    t_start_total = time.perf_counter()

    gc.collect()
    gc.disable()

    for i in range(WARMUP):
        ascon_lib.decrypt_ascon128(KEY, c_nonce, c_cipher, c_decrypted, c_tag, DATA_SIZE)

    for i in range(WARMUP, TRIALS + WARMUP):
        start = time.perf_counter_ns()
        ascon_lib.decrypt_ascon128(KEY, c_nonce, c_cipher, c_decrypted, c_tag, DATA_SIZE)
        end = time.perf_counter_ns()

        cpu_pct = process.cpu_percent(interval=None)
        results.append((end - start, process.memory_info().rss, cpu_pct))

    gc.enable()

    # --- SELESAI TIMING TOTAL ---
    t_end_total = time.perf_counter()
    waktu_total = t_end_total - t_start_total

    with open(METRICS_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Trial", "Dec_Latency_ns", "Dec_RAM_Bytes", "CPU_Percent", "Dec_Throughput_bps"])
        for idx, (lat, mem, cpu) in enumerate(results):
            throughput = (DATA_SIZE * 8) / (lat / 1e9)
            writer.writerow([idx + 1, lat, mem, cpu, f"{throughput:.2f}"])

    print(f"Selesai! Metrik dekripsi disimpan di {METRICS_FILE}")
    print(f"Waktu Eksekusi Total Loop: {waktu_total:.6f} detik")

if __name__ == "__main__":
    run_decryption_test()
