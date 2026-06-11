import sys
import ctypes
import time
import csv
import os
import gc
import psutil

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Usage: python3 decrypt_benchmark_speck.py <file.enc> [trials]")
    sys.exit(1)

INPUT_FILE = sys.argv[1]
TRIALS = int(sys.argv[2]) if len(sys.argv) == 3 else 1000
WARMUP = 50

KEY = b'PolibatamRKS2026'

METRICS_FILE = INPUT_FILE + "_decrypt_metrics.csv"

try:
    speck_lib = ctypes.CDLL('./libspeck_core.so')

    speck_lib.decrypt_speck128.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t
    ]

except OSError:
    print("libspeck_core.so tidak ditemukan")
    sys.exit(1)
def run_decryption_test():

    if not os.path.exists(INPUT_FILE):
        print("File ciphertext tidak ditemukan")
        sys.exit(1)

    with open(INPUT_FILE, "rb") as f:
        payload = f.read()

    iv = payload[:16]
    ciphertext = payload[16:]

    DATA_SIZE = len(ciphertext)

    c_input = ctypes.create_string_buffer(ciphertext)
    c_output = ctypes.create_string_buffer(DATA_SIZE)

    process = psutil.Process(os.getpid())

    results = []

    print(f"Memuat file : {INPUT_FILE}")
    print(f"Ukuran      : {DATA_SIZE} bytes")
    print(f"Trial       : {TRIALS}")

    gc.collect()
    gc.disable()

    total_start = time.perf_counter()
    for _ in range(WARMUP):

        speck_lib.decrypt_speck128(
            KEY,
            ctypes.create_string_buffer(iv),
            c_input,
            c_output,
            DATA_SIZE
        )

    for _ in range(TRIALS):

        start = time.perf_counter_ns()

        speck_lib.decrypt_speck128(
            KEY,
            ctypes.create_string_buffer(iv),
            c_input,
            c_output,
            DATA_SIZE
        )

        end = time.perf_counter_ns()

        latency = end - start

        ram = process.memory_info().rss
        cpu = process.cpu_percent(interval=None)

        results.append((latency, ram, cpu))
    gc.enable()

    total_end = time.perf_counter()

    with open(METRICS_FILE, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "Trial",
            "Latency_ns",
            "RAM_Bytes",
            "CPU_Percent",
            "Throughput_bps"
        ])

        for idx, (lat, ram, cpu) in enumerate(results):

            throughput = (DATA_SIZE * 8) / (lat / 1e9)

            writer.writerow([
                idx + 1,
                lat,
                ram,
                cpu,
                f"{throughput:.2f}"
            ])

    print(f"Metrics file : {METRICS_FILE}")
    print(f"Total Time   : {total_end - total_start:.6f} sec")
if __name__ == "__main__":
    run_decryption_test()
