import time

def stress():
    while True:
        x = 12345 * 67890
        y = x / 123

if __name__ == "__main__":
    import multiprocessing
    processes = []
    for _ in range(16): # 16 cores
        p = multiprocessing.Process(target=stress)
        p.start()
        processes.append(p)
    while True:
        time.sleep(1)
