import os
import yaml
from colorama import Fore, Style, init

from sorx import __version__
from sorx.data.loader.rule import get_rule
from sorx.checks.cors_analyze import analyze

init(autoreset=True)


SEVERITY_COLORS = {
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.GREEN,
    "info": "\033[38;5;250m",
}

GREY = "\033[38;5;250m"


def logo():
    return fr"""
    {Fore.LIGHTRED_EX}     _____   ____   ____   _  __ {Style.RESET_ALL}
    {Fore.LIGHTRED_EX}    (  ___| (    \ (  ,_\ ( \/ / {Style.RESET_ALL}
    {Fore.LIGHTRED_EX}     \___  \ \  \ \ \ \    :  : {Style.RESET_ALL}
    {Fore.LIGHTRED_EX}      |_____) \____) \_)  /_/\_) {Style.RESET_ALL} {Fore.LIGHTYELLOW_EX}v{__version__}{Style.RESET_ALL}
    
        {Fore.LIGHTYELLOW_EX}https://github.com/Pupsix/sorx{Style.RESET_ALL}
    """


def load_rules():
    current_dir = os.path.dirname(__file__)
    rules_path = os.path.abspath(
        os.path.join(
            current_dir,
            "..",
            "checks",
            "cors_rules.yaml",
        )
    )

    try:
        with open(rules_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        return data.get("rules", [])

    except (FileNotFoundError, yaml.YAMLError):
        return []


def get_severity(finding_id):
    rule = get_rule(finding_id)

    if rule:
        return rule.get("severity", "info").lower()

    return "info"


def header(stat):
    print(
        f"Targets: {stat.targets} | "
        f"Mode: {stat.mode} | "
        f"Threads: {stat.threads}"
    )


def findings(url, target_findings, errors):
    print()
    print(f"{Fore.YELLOW}{url}{Style.RESET_ALL}")

    if errors:
        if "timeout" in errors:
            print(f"  {GREY}[Timeout]{Style.RESET_ALL}")
        elif "connection" in errors:
            print(f"  {GREY}[Connection error]{Style.RESET_ALL}")
        else:
            print(f"  {GREY}[Request error]{Style.RESET_ALL}")
        return

    if not target_findings:
        print(f"  {GREY}[No findings]{Style.RESET_ALL}")
        return

    for finding in target_findings:
        finding_id = finding[0]
        name = finding[1]

        severity = get_severity(finding_id)
        color = SEVERITY_COLORS.get(severity, GREY)

        print(
            f"  {color}[{finding_id}]{Style.RESET_ALL} {name}"
        )


def summary(stat):
    print()
    print("─" * 44)

    print("Scan completed")
    print()

    print(f"Targets scanned : {stat.scanned}")
    print(f"Errors          : {stat.error}")
    print(f"Requests        : {stat.request}")
    print(f"Time            : {stat.elapsed}")
    print(f"Output          : {stat.output}")

    print("─" * 44)


# Utils
def show_id_details(rule_id):
    rule = get_rule(rule_id)

    if not rule:
        print(f"{Fore.RED}sorx: CORS ID '{rule_id}' not found{Style.RESET_ALL}")
        return

    severity = rule.get("severity", "info").lower()
    severity_color = SEVERITY_COLORS.get(severity, GREY)

    print(f"\n{Fore.YELLOW}* {rule['id']}{Style.RESET_ALL}  - {Fore.WHITE}{rule['title']}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}* Severity: {Style.RESET_ALL}{severity_color}{rule['severity']}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}* Description:{Style.RESET_ALL}")
    print(f"   - {rule['description'].strip()}")

    print(f"{Fore.YELLOW}* Evidence:{Style.RESET_ALL}")
    print(f"   - {rule['evidence'].strip()}")

    print(f"{Fore.YELLOW}* Suggestion:{Style.RESET_ALL}")
    print(f"   - {rule['suggestion'].strip()}")

    note = rule.get("note")

    if note:
        print(f"{Fore.YELLOW}* Note:{Style.RESET_ALL}")

        for line in note.strip().splitlines():
            print(f"   - {line}")

    example = rule.get("example")

    if example:
        print(f"{Fore.YELLOW}* Example:{Style.RESET_ALL}")

        if example.get("request"):
            print(f"   {Fore.CYAN}Request:{Style.RESET_ALL}")

            for line in example["request"].strip().splitlines():
                print(f"      {line}")

        if example.get("response"):
            print(f"   {Fore.CYAN}Response:{Style.RESET_ALL}")

            for line in example["response"].strip().splitlines():
                print(f"      {line}")


def show_verbose(results):
    REQUEST_HEADER_BLACKLIST = {
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "priority",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "upgrade-insecure-requests",
    }

    RESPONSE_HEADER_BLACKLIST = {
        "x-xss-protection",
        "x-frame-options",
        "date",
        "content-security-policy",
        "via",
        "content-type",
        "cf-cache-status",
        "etag",
        "cache-control",
        "expires",
        "age",
        "server",
        "transfer-encoding",
        "fly-request-id",
        "last-modified",
        "cf-ray",
        "connection",
        "content-encoding",
    }

    for url, outputs in results.items():

        for result in outputs:
            task = result.get("task", {})
            response = result.get("response")
            error = result.get("error")

            method = task.get("method", "GET")
            target = task.get("url", url)
            headers = task.get("headers", {})
            data = task.get("data")

            # Analyze
            findings = []

            if response is not None and error is None:
                findings = analyze(response=response, task=task,)

            # Request
            print(f"\n{Fore.YELLOW}Request:{Style.RESET_ALL}")
            print(f"  {method} {target}")

            for name, value in headers.items():
                if name.lower() not in REQUEST_HEADER_BLACKLIST:
                    print(f"  {name}: {value}")

            if data:
                print(f"\n  {data}")

            # Error
            if error:
                print(f"\n{Fore.RED}Error:{Style.RESET_ALL} {error}")
                print("\n" + "─" * 44)
                continue

            # Response
            print(f"\n{Fore.YELLOW}Response:{Style.RESET_ALL}")

            if response is None:
                print("  No response")
                print("\n" + "─" * 44)
                continue

            print(f"  HTTP {response.status_code}")

            for name, value in response.headers.items():
                if name.lower() not in RESPONSE_HEADER_BLACKLIST:
                    print(f"  {name}: {value}")

            # CORS IDs
            if findings:
                print(f"\n{Fore.YELLOW}CORS:{Style.RESET_ALL}")

                for finding_id, title in findings:
                    severity = get_severity(finding_id)
                    color = SEVERITY_COLORS.get(severity, GREY,)

                    print(f"  [{color}{finding_id}{Style.RESET_ALL}] {title}")
            print("\n" + "─" * 44)