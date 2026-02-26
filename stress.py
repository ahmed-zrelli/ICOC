import multiprocessing
import math

def stress():
    while True:
        math.sqrt(math.pow(1234.5678, 910.1112))

if __name__ == "__main__":
    processes = []
    for _ in range(12):
        p = multiprocessing.Process(target=stress)
        p.start()
        processes.append(p)
    for p in processes:
        p.join()
