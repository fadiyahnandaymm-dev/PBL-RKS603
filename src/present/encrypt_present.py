import sys
import ctypes
import time
import csv
import os
import gc
import psutil

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Cara Penggunaan: python3 encrypt_benchmark.py <nama_file.txt> [jumlah_trials]")
    sys.exit(1)

INPUT_FILE = sys.argv[1]
TRIALS = int(sys.argv[2]) if len(sys.argv) == 3 else 1000
WARMUP = 0
KEY = b'PolibatamR' # Kunci 10 Byte (80-bit) untuk PRESENT-80

OUTPUT_FILE = INPUT_FILE + '.enc'
METRICS_FILE = INPUT_FILE + '_encrypt_metrics.csv'

try:
    present_lib = ctypes.CDLL('./libpresent_core.so')
    # Argumen: key, plaintext, ciphertext, len
    present_lib.present_encrypt_bulk.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
    ]
except OSError:
    print("Error: libpresent_core.so tidak ditemukan.")
    sys.exit(1)

def pad(data):
    # Padding kelipatan 8 byte untuk PRESENT
    padding_len = 8 - (len(data) % 8)
    return data + bytes([padding_len] * padding_len)

def run_encryption_test():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: '{INPUT_FILE}' tidak ditemukan.")
        sys.exit(1)
        
    with open(INPUT_FILE, 'rb') as f:
        plaintext = f.read()
        
    padded_data = pad(plaintext)
    DATA_SIZE = len(padded_data)
    
    c_input = ctypes.create_string_buffer(padded_data)
    c_encrypted = ctypes.create_string_buffer(DATA_SIZE)
    
    process = psutil.Process(os.getpid())
    results = []

    print(f"Memuat '{INPUT_FILE}' ({DATA_SIZE} bytes).")
    print(f"Memulai {TRIALS} Percobaan Enkripsi PRESENT Eksklusif...")
    
    # --- MULAI TIMING TOTAL ---
    t_start_total = time.perf_counter()
    
    gc.collect()
    gc.disable()
    
    for _ in range(WARMUP):
        present_lib.present_encrypt_bulk(KEY, c_input, c_encrypted, DATA_SIZE)
        
    for _ in range(TRIALS):
        start = time.perf_counter_ns()
        present_lib.present_encrypt_bulk(KEY, c_input, c_encrypted, DATA_SIZE)
        end = time.perf_counter_ns()
        
        cpu_pct = process.cpu_percent(interval=None)
        results.append((end - start, process.memory_info().rss, cpu_pct))
        
    gc.enable()
    
    # --- SELESAI TIMING TOTAL ---
    t_end_total = time.perf_counter()
    waktu_total = t_end_total - t_start_total

    # Simpan hasil enkripsi langsung tanpa metadata IV
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(c_encrypted.raw)
        
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
