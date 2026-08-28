import threading
from queue import Queue

import requests

from sorx import __version__


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


def worker(q, results):
    while True:
        job = q.get()

        if job is None:
            q.task_done()
            break

        try:
            results.put({"task": job, "response": request(job), "error": None})
        except requests.exceptions.Timeout:
            results.put({"task": job, "response": None, "error": "timeout"})
        except requests.exceptions.ConnectionError:
            results.put({"task": job, "response": None, "error": "connection"})
        except requests.exceptions.RequestException:
            results.put({"task": job, "response": None, "error": "request"})
        finally:
            q.task_done()


def run(jobs, workers):
    q, results, threads = Queue(), Queue(), []

    for _ in range(workers):
        t = threading.Thread(target=worker, args=(q, results), daemon=True)
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