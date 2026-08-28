import os
import yaml
from colorama import Fore, Style, init

from sorx import __version__

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