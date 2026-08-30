import threading
from queue import Queue
import time
import requests

from sorx import __version__


request_lock = threading.Lock()
last_request_time = 0.0


def wait_for_delay(delay):
    global last_request_time

    if not delay or delay <= 0:
        return

    with request_lock:
        now = time.monotonic()
        elapsed = now - last_request_time

        if elapsed < delay:
            time.sleep(delay - elapsed)

        last_request_time = time.monotonic()



def wait_for_rate(rate):
    global last_request_time

    if not rate or rate <= 0:
        return

    interval = 1.0 / rate

    with request_lock:
        now = time.monotonic()
        elapsed = now - last_request_time

        if elapsed < interval:
            time.sleep(interval - elapsed)

        last_request_time = time.monotonic()


def request(job):
    headers = job.get("headers", {}).copy()
    headers.setdefault("User-Agent", f"sorx/{__version__}")

    return requests.request(
        method=job["method"],
        url=job["url"],
        headers=headers,
        timeout=job.get("timeout", 10),
        data=job.get("data"),
    )


def worker(q, results, delay=0, rate=0):
    while True:
        job = q.get()

        if job is None:
            q.task_done()
            break

        try:
            wait_for_delay(delay)
            wait_for_rate(rate)

            results.put({"task": job, "response": request(job), "error": None})

        except requests.exceptions.Timeout:
            results.put({"task": job, "response": None, "error": "timeout"})

        except requests.exceptions.ConnectionError:
            results.put({"task": job, "response": None, "error": "connection"})

        except requests.exceptions.RequestException:
            results.put({"task": job, "response": None, "error": "request"})

        finally:
            q.task_done()


def run(jobs, workers, delay=0, rate=0):
    q, results, threads = Queue(), Queue(), []

    for _ in range(workers):
        t = threading.Thread(target=worker, args=(q, results, delay, rate), daemon=True)
        t.start()
        threads.append(t)

    for job in jobs:
        q.put(job)

    q.join()

    for _ in threads:
        q.put(None)

    for t in threads:
        t.join()

    output = []

    while not results.empty():
        output.append(results.get())

    return output
