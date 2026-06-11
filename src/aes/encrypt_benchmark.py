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
WARMUP = 50
KEY = b'PolibatamRKS2026'

OUTPUT_FILE = INPUT_FILE + '.enc'
METRICS_FILE = INPUT_FILE + '_encrypt_metrics.csv'

try:
    aes_lib = ctypes.CDLL('./libaes_core.so')
    aes_lib.encrypt_aes128.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
    ]
except OSError:
    print("Error: libaes_core.so tidak ditemukan.")
    sys.exit(1)

def pad(data):
    padding_len = 16 - (len(data) % 16)
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
    iv_pool = [os.urandom(16) for _ in range(TRIALS + WARMUP)]
    
    process = psutil.Process(os.getpid())
    results = []

    print(f"Memuat '{INPUT_FILE}' ({DATA_SIZE} bytes).")
    print(f"Memulai {TRIALS} Percobaan Enkripsi Eksklusif...")
    
    # --- MULAI TIMING TOTAL ---
    t_start_total = time.perf_counter()
    
    gc.collect()
    gc.disable()
    
    for i in range(WARMUP):
        aes_lib.encrypt_aes128(KEY, ctypes.create_string_buffer(iv_pool[i]), c_input, c_encrypted, DATA_SIZE)
        
    for i in range(WARMUP, TRIALS + WARMUP):
        iv = ctypes.create_string_buffer(iv_pool[i])
        
        start = time.perf_counter_ns()
        aes_lib.encrypt_aes128(KEY, iv, c_input, c_encrypted, DATA_SIZE)
        end = time.perf_counter_ns()
        
        cpu_pct = process.cpu_percent(interval=None)
        results.append((end - start, process.memory_info().rss, cpu_pct))
        
    gc.enable()
    
    # --- SELESAI TIMING TOTAL ---
    t_end_total = time.perf_counter()
    waktu_total = t_end_total - t_start_total

    with open(OUTPUT_FILE, 'wb') as f:
        f.write(iv_pool[-1] + c_encrypted.raw)
        
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
