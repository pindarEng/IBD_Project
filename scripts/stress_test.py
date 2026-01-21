import threading
import requests
import time
import sys

URL = "http://localhost:30001/scan/"
CONCURRENT_USERS = 50  
PAYLOAD = {"url": "http://stress-test-url.com/malware-check"}

request_count = 0

def attack_worker():
    global request_count
    while True:
        try:

            resp = requests.post(URL, json=PAYLOAD, timeout=2)
            if resp.status_code == 200:
                request_count += 1
        except :
            pass 

def monitor():
    start_time = time.time()
    while True:
        time.sleep(1)
        elapsed = time.time() - start_time
        rps = request_count / elapsed
        sys.stdout.write(f"\r[Attack in Progress] Requests sent: {request_count} | Speed: {rps:.2f} req/sec")
        sys.stdout.flush()


threading.Thread(target=monitor, daemon=True).start()


threads = []
for i in range(CONCURRENT_USERS):
    t = threading.Thread(target=attack_worker, daemon=True)
    t.start()
    threads.append(t)


try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopping attack...")