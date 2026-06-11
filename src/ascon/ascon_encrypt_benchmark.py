import sys
import ctypes
import time
import csv
import os
import gc
import psutil

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Cara Penggunaan: python3 ascon_encrypt_benchmark.py <nama_file> [jumlah_trials]")
    sys.exit(1)

INPUT_FILE   = sys.argv[1]
TRIALS       = int(sys.argv[2]) if len(sys.argv) == 3 else 1000
WARMUP       = 50
KEY          = b'PolibatamRKS2026'
OUTPUT_FILE  = INPUT_FILE + '.enc'
METRICS_FILE = INPUT_FILE + '_encrypt_metrics.csv'

try:
    ascon_lib = ctypes.CDLL('./libascon_core.so')
    ascon_lib.encrypt_ascon128.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
    ]
    ascon_lib.encrypt_ascon128.restype = None
except OSError:
    print("Error: libascon_core.so tidak ditemukan.")
    sys.exit(1)

def run_encryption_test():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: '{INPUT_FILE}' tidak ditemukan.")
        sys.exit(1)

    with open(INPUT_FILE, 'rb') as f:
        plaintext = f.read()

    DATA_SIZE  = len(plaintext)
    out_size   = DATA_SIZE + 16
    c_input    = ctypes.create_string_buffer(plaintext)
    c_output   = ctypes.create_string_buffer(out_size)
    nonce_pool = [os.urandom(16) for _ in range(TRIALS + WARMUP)]

    process = psutil.Process(os.getpid())
    results = []

    print(f"Memuat '{INPUT_FILE}' ({DATA_SIZE} bytes).")
    print(f"Memulai {TRIALS} Percobaan Enkripsi Eksklusif...")

    # --- MULAI TIMING TOTAL ---
    t_start_total = time.perf_counter()

    gc.collect()
    gc.disable()

    for i in range(WARMUP):
        ascon_lib.encrypt_ascon128(KEY, ctypes.create_string_buffer(nonce_pool[i]), c_input, c_output, DATA_SIZE)

    for i in range(WARMUP, TRIALS + WARMUP):
        nonce = ctypes.create_string_buffer(nonce_pool[i])

        start = time.perf_counter_ns()
        ascon_lib.encrypt_ascon128(KEY, nonce, c_input, c_output, DATA_SIZE)
        end = time.perf_counter_ns()

        cpu_pct = process.cpu_percent(interval=None)
        results.append((end - start, process.memory_info().rss, cpu_pct))

    gc.enable()

    # --- SELESAI TIMING TOTAL ---
    t_end_total = time.perf_counter()
    waktu_total = t_end_total - t_start_total

    # Simpan file .enc: nonce(16) + ciphertext+tag
    last_nonce = nonce_pool[-1]
    ascon_lib.encrypt_ascon128(KEY, ctypes.create_string_buffer(last_nonce), c_input, c_output, DATA_SIZE)
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(last_nonce + c_output.raw)

    with open(METRICS_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Trial", "Enc_Latency_ns", "Enc_RAM_Bytes", "CPU_Percent", "Enc_Throughput_bps"])
        for idx, (lat, mem, cpu) in enumerate(results):
            throughput = (DATA_SIZE * 8) / (lat / 1e9)
            writer.writerow([idx + 1, lat, mem, cpu, f"{throughput:.2f}"])

    print(f"Selesai! File disimpan: {OUTPUT_FILE} | Metrik: {METRICS_FILE}")
    print(f"Waktu Eksekusi Total Loop: {waktu_total:.6f} detik")

if __name__ == "__main__":
    run_encryption_test()
