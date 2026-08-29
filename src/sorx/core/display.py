import os
import yaml
from colorama import Fore, Style, init

from sorx import __version__
from sorx.data.loader.rule import get_rule

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
        ______  _____  _____  __  __
        \  ___| \    \ \  ,_\ \ \/ /
         \___  \ \  \ \ \ \    :  :
          \_____) \____) \_)  /_/\_\ v{__version__}
    
        https://github.com/Pupsix/sorx
    """


def load_rules():
    current_dir = os.path.dirname(__file__)
    rules_path = os.path.join(
        current_dir,
        "..",
        "checks",
        "cors_rules.yaml",
    )

    rules_path = os.path.abspath(rules_path)

    try:
        with open(rules_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        return data.get("rules", [])

    except (FileNotFoundError, yaml.YAMLError):
        return []


def get_severity(finding_id):
    rules = load_rules()

    for rule in rules:
        if rule.get("id") == finding_id:
            return rule.get("severity", "info").lower()

    return "info"


def header(stat):
    print(f"  Targets: {stat.targets} | Mode: {stat.mode} | Threads: {stat.threads}")


def findings(url, target_findings, errors):
    print()
    print(f"  {Fore.YELLOW}{url}{Style.RESET_ALL}")

    if errors:
        if "timeout" in errors:
            print(f"    {GREY}[Timeout]{Style.RESET_ALL}")
        elif "connection" in errors:
            print(f"    {GREY}[Connection error]{Style.RESET_ALL}")
        else:
            print(f"    {GREY}[Request error]{Style.RESET_ALL}")

        return

    if not target_findings:
        print(f"    {GREY}[No findings]{Style.RESET_ALL}")
        return

    for finding in target_findings:
        finding_id = finding[0]
        name = finding[1]

        severity = get_severity(finding_id)
        color = SEVERITY_COLORS.get(severity, GREY)

        print(f"    {color}[{finding_id}]{Style.RESET_ALL} {name}")


def summary(stat):
    print()
    print("─" * 44)

    print("  Scan completed")
    print()

    print(f"  Targets scanned : {stat.scanned}")
    print(f"  Errors          : {stat.error}")
    print(f"  Requests        : {stat.request}")
    print(f"  Time            : {stat.elapsed}")
    print(f"  Output          : {stat.output}")

    print("─" * 44)


# Utils
def show_id_details(rule_id):
    rule = get_rule(rule_id)

    if not rule:
        print(f"{Fore.RED}sorx: CORS ID '{rule_id}' not found{Style.RESET_ALL}")
        return

    severity = rule["severity"].lower()

    severity_color = {
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.GREEN,
        "info": "\033[38;5;250m",
    }.get(severity, Fore.WHITE)

    def print_block(label, content):
        print(f"{Fore.CYAN}   {label}:{Style.RESET_ALL}")

        for line in content.strip().splitlines():
            print(f"      {line}")

    print(f"\n{Fore.YELLOW}* {rule['id']}{Style.RESET_ALL}  - {Fore.WHITE}{rule['title']}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}* Severity: {Style.RESET_ALL}{severity_color}{rule['severity']}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}* Description:{Style.RESET_ALL}")
    print(f"   - {rule['description'].strip()}")

    print(f"{Fore.YELLOW}* Evidence:{Style.RESET_ALL}")
    print(f"   - {rule['evidence'].strip()}")

    print(f"{Fore.YELLOW}* Suggestion:{Style.RESET_ALL}")
    print(f"   - {rule['suggestion'].strip()}")

    example = rule.get("example")
    note = rule.get("note")


def show_verbose(results):
    REQUEST_HEADER_BLACKLIST = {}
    RESPONSE_HEADER_BLACKLIST = {}

    for url, outputs in results.items():

        for result in outputs:
            task = result.get("task", {})
            response = result.get("response")
            error = result.get("error")

            method = task.get("method", "GET")
            target = task.get("url", url)
            headers = task.get("headers", {})
            data = task.get("data")

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
                continue

            # Response
            print(f"\n{Fore.YELLOW}Response:{Style.RESET_ALL}")

            if response is None:
                print("  No response")
                continue

            print(f"  HTTP {response.status_code}")

            for name, value in response.headers.items():
                if name.lower() not in RESPONSE_HEADER_BLACKLIST:
                    print(f"  {name}: {value}")
            print("")
            print("─" * 44)