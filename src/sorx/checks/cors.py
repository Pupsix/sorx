import time
from urllib.parse import urlparse
import tldextract

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
        self.delay = config.get("delay")
        self.rate = config.get("rate")
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
    origin=None,
    request_method=None,
    request_headers=None,
):
    return {
        "url": url,
        "method": method,
        "headers": headers or {},
        "data": data,
        "timeout": timeout,
        "origin": origin or "",
        "request_method": request_method,
        "request_headers": request_headers,
    }

def get_trust_parts(url):
    hostname = urlparse(url).hostname or ""

    # IP address / localhost
    if (
        hostname == "localhost"
        or all(part.isdigit() and 0 <= int(part) <= 255
               for part in hostname.split("."))
        and len(hostname.split(".")) == 4
    ):
        return {
            "TRUST_HOSTNAME": hostname,
            "TRUST_HOSTNAME_UPPERCASE": hostname.upper(),
            "TRUST_DOMAIN": hostname,
            "TRUST_DOMAIN_NAME": hostname,
            "TRUST_SUBDOMAIN": "",
        }

    extracted = tldextract.extract(hostname)

    domain_name = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain

    domain = (
        f"{domain_name}.{suffix}"
        if suffix
        else domain_name
    )

    return {
        "TRUST_HOSTNAME": hostname,
        "TRUST_HOSTNAME_UPPERCASE": hostname.upper(),
        "TRUST_DOMAIN": domain,
        "TRUST_DOMAIN_NAME": domain_name,
        "TRUST_SUBDOMAIN": subdomain,
    }


def get_payloads(mode):
    priority_map = {
        "quick": ["high_priority"],
        "normal": ["high_priority", "medium_priority"],
        "deep": ["high_priority", "medium_priority", "low_priority"],
    }

    priorities = priority_map.get(mode, [])

    origin = load_payload("origin").get("origin", {})
    header = load_payload("header").get("header", {})
    method = load_payload("method").get("method", {})

    origin_payloads = []
    header_payloads = []
    method_payloads = []

    for priority in priorities:
        origin_payloads.extend(origin.get(priority, []))
        header_payloads.extend(header.get(priority, []))
        method_payloads.extend(method.get(priority, []))

    return {
        "origin": origin_payloads,
        "header": header_payloads,
        "method": method_payloads,
    }


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
    base_headers = config.get("headers", {})
    jobs = []
    trust = get_trust_parts(url)
    payloads = get_payloads(mode)

    origin_payloads = payloads["origin"]
    header_payloads = payloads["header"]
    method_payloads = payloads["method"]

    # Simple requests
    for payload in origin_payloads:
        origin = payload

        for key, value in trust.items():
            origin = origin.replace(f"{{{key}}}", value)

        jobs.append(
            create_job(
                url=url,
                method="GET",
                headers={**base_headers, "Origin": origin},
                origin=origin,
            )
        )

    # Preflight requests
    attacker_origin = "https://attacker.example"

    if not mode:
        return jobs

    if mode == "quick":
        jobs.append(
            create_job(
                url=url,
                method="OPTIONS",
                headers={
                    **base_headers,
                    "Origin": attacker_origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization",
                },
                origin=attacker_origin,
                request_method="POST",
                request_headers="Authorization",
            )
        )

    elif mode == "normal":
        jobs.extend([
            create_job(
                url=url,
                method="OPTIONS",
                headers={
                    **base_headers,
                    "Origin": attacker_origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Authorization",
                },
                origin=attacker_origin,
                request_method="POST",
                request_headers="Authorization",
            ),
            create_job(
                url=url,
                method="OPTIONS",
                headers={
                    **base_headers,
                    "Origin": attacker_origin,
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "Content-Type",
                },
                origin=attacker_origin,
                request_method="PUT",
                request_headers="Content-Type",
            ),
        ])

    elif mode == "deep":
        preflight_jobs = []

        for method in method_payloads[:3]:
            preflight_jobs.append(
                create_job(
                    url=url,
                    method="OPTIONS",
                    headers={
                        **base_headers,
                        "Origin": attacker_origin,
                        "Access-Control-Request-Method": method,
                    },
                    origin=attacker_origin,
                    request_method=method,
                )
            )

        remaining = 5 - len(preflight_jobs)

        for header in header_payloads[:remaining]:
            preflight_jobs.append(
                create_job(
                    url=url,
                    method="OPTIONS",
                    headers={
                        **base_headers,
                        "Origin": attacker_origin,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": header,
                    },
                    origin=attacker_origin,
                    request_method="POST",
                    request_headers=header,
                )
            )

        jobs.extend(preflight_jobs)

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
        results = requester_run(jobs=jobs, workers=workers, delay=config.get("delay"), rate=config.get("rate"))

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