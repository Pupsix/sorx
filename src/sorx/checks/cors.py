import time
from urllib.parse import urlparse

from sorx.checks.cors_analyze import analyze
from sorx.core.display import header
from sorx.core.requester import run as requester_run
from sorx.data.loader.payload import load_payload


class Stat:
    def __init__(self, targets, mode, threads, config):
        self.targets_list, self.targets = list(targets), len(targets)
        self.mode, self.threads = mode, threads
        self.header = config.get("headers", {})
        self.scanned = 0
        self.findings = {url: [] for url in targets}
        self.errors = {url: [] for url in targets}
        self.start_time = time.time()
        self.error = self.request = 0
        self.results = {}
        self.elapsed = "00:00"
        self.output = config.get("output") or "None"


def create_job(
    url,
    method="GET",
    headers=None,
    data=None,
    timeout=10,
    origin=None
):
    return {
        "url": url,
        "method": method,
        "headers": headers or {},
        "data": data,
        "timeout": timeout,
        "origin": origin or "",
    }


def get_payloads(name, mode):
    payloads = load_payload(name).get(name, {})

    priority_map = {
        "quick": ["high_priority"],
        "normal": ["high_priority", "medium_priority"],
        "deep": ["high_priority", "medium_priority", "low_priority"],
    }

    result = []

    for priority in priority_map.get(mode, []):
        result.extend(payloads.get(priority, []))

    return result


def passive(url, config):
    return [
        create_job(
            url=url,
            method=config.get("method", "GET"),
            headers=config.get("headers", {}),
            data=config.get("data"),
            timeout=config.get("timeout", 10),
        )
    ]


def active(url, config, trust_hostname):
    mode = config.get("mode")
    timeout = config.get("timeout", 10)
    base_headers = config.get("headers", {})

    jobs = []

    for origin in get_payloads("origin", mode):
        origin = origin.replace("{TRUST_HOSTNAME}", trust_hostname)

        origin = origin.replace("{TRUST_HOSTNAME_UPPERCASE}", trust_hostname.upper())

        jobs.append(
            create_job(
                url=url,
                method="GET",
                headers={
                    **base_headers,
                    "Origin": origin
                },
                timeout=timeout,
                origin=origin
            )
        )

    jobs.append(
        create_job(
            url=url,
            method="OPTIONS",
            headers={
                **base_headers,
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization",
            },
            timeout=timeout,
            origin="https://attacker.example",
        )
    )

    return jobs


def update_elapsed(stat):
    elapsed = time.time() - stat.start_time
    stat.elapsed = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"


def analyze_results(stat, results):
    for result in results:
        task = result.get("task")

        if not task:
            continue

        target_url = task.get("url")

        if target_url not in stat.findings:
            continue

        error = result.get("error")

        if error is not None:
            stat.error += 1

            if error not in stat.errors[target_url]:
                stat.errors[target_url].append(error)

            continue

        response = result.get("response")

        if response is None:
            continue

        for finding in analyze(
            response=response,
            task=task
        ):
            if finding not in stat.findings[target_url]:
                stat.findings[target_url].append(finding)


def run(urls, config, on_target_done=None):
    mode = config.get("mode")
    mode_name = "passive" if mode is None else mode
    workers = config.get("workers", 10)

    urls = [urls] if isinstance(urls, str) else list(urls)

    stat = Stat(targets=urls, mode=mode_name, threads=workers, config=config)

    header(stat)

    for url in urls:

        # Get hostname directly from target URL
        trust_hostname = urlparse(url).hostname or ""

        # Generate jobs
        if mode is None:
            jobs = passive(url=url, config=config)
        else:
            jobs = active(url=url, config=config,trust_hostname=trust_hostname)

        stat.request += len(jobs)

        # Send requests
        results = requester_run(jobs=jobs, workers=workers)

        # Store raw requester output
        stat.results[url] = results

        # Analyze
        analyze_results(stat=stat, results=results)

        # Target finished
        stat.scanned += 1
        update_elapsed(stat)

        if on_target_done:
            on_target_done(url, stat.findings[url], stat.errors[url])

    update_elapsed(stat)

    return stat