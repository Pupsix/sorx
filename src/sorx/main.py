import argparse
import re
import sys
import requests
from colorama import Fore, Style, init

from sorx import __version__
from sorx.checks.cors import run as cors_run
from sorx.core import display, reporter
from sorx.core.display import show_id_details, show_verbose
from sorx.core.requester import run

init(autoreset=True)


class SorxParser(argparse.ArgumentParser):
    def error(self, message):
        print(display.logo())
        self.print_usage()
        print(f"\nsorx: error: {message}\n")
        raise SystemExit(2)


def build_flags():
    parser = SorxParser(
        prog="sorx",
        description="A tool for analyzing CORS headers",
        add_help=True,
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog,
            max_help_position=30,
            width=120,
        ),
        epilog="""Examples:
    sorx -u https://example.com -o result.txt    # Output in TXT
    sorx -u https://example.com -j result.json   # Output in JSON
    sorx -l targets.txt -m quick -t 20           # Scan a list of targets

[?] How to get better results with sorx?
- Use list scans for quick reconnaissance. When a target has findings worth investigating, rerun sorx with `--verbose` on that target to view the full evidence.
- If you're scanning a single target, I recommend using `--verbose`.
- Due to UI limitations, displaying full details for every target would generate an excessive amount of output. For example, scanning 100 targets could produce 500–1,000 lines of output.

""")

    parser.add_argument("-v", "--version", action="store_true", help="Show version and check for updates")
    parser.add_argument("-u", "--url", dest="url", type=str, help="Target URL")
    parser.add_argument("-l", "--list", dest="list", type=str, help="File containing target URLs")
    parser.add_argument("-H", "--header", dest="header", type=str, help="Custom header <e.g., 'Hackerone: abcxyz'>")
    parser.add_argument("-X", "--method", dest="method", type=str, default="GET", help="HTTP method (default: GET)")
    parser.add_argument("-D", "--data", dest="data", type=str, help="Request body data")
    parser.add_argument("--timeout", dest="timeout", type=int, default=6, help="Request timeout in seconds (default: 6)")
    parser.add_argument("-t", "--thread", dest="thread", type=int, default=15, help="Number of threads (default: 15)")
    parser.add_argument("-m", "--mode", dest="mode", choices=["quick", "normal", "deep"], metavar="MODE", default=None, help="Enable active CORS fuzzing: [quick, normal, deep]. Omit for passive mode.")
    parser.add_argument("--rule", dest="rule", nargs="+", type=str, help="Show CORS finding details")
    parser.add_argument("--verbose", dest="verbose", action="store_true", help="Show full evidence")
    parser.add_argument("-o", "--output", dest="output", type=str, help="Output file path")
    parser.add_argument("-j", "--json", dest="json", type=str, help="Output results in JSON format")

    return parser


def get_latest_version():
    try:
        response = requests.get("https://pypi.org/pypi/sorx/json", timeout=3)
        response.raise_for_status()
        return response.json()["info"]["version"]
    except requests.exceptions.RequestException:
        return None


def show_version():
    latest = get_latest_version()

    if latest is None:
        print(f"sorx {__version__} {Fore.LIGHTBLACK_EX}[Unable to check for updates. Please check manually.]{Style.RESET_ALL}")
        print("https://pypi.org/project/sorx/")
    elif latest == __version__:
        print(f"sorx {__version__} {Fore.GREEN}[Latest]{Style.RESET_ALL}")
    else:
        print(f"sorx {__version__} {Fore.YELLOW}[Outdated, latest is {latest}]{Style.RESET_ALL}")


def is_valid_url(url):
    pattern = re.compile(
        r"^https?://(?:(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?:/[^\s]*)?$",
        re.IGNORECASE,
    )
    return bool(pattern.match(url))


def load_targets(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            targets = [line.strip() for line in file if line.strip() and is_valid_url(line.strip())]
    except FileNotFoundError:
        raise ValueError(f"target list not found: {path}")
    except PermissionError:
        raise ValueError(f"permission denied: {path}")
    except OSError as err:
        raise ValueError(f"unable to read target list: {err}")

    unique_targets = list(dict.fromkeys(targets))

    if not unique_targets:
        raise ValueError(f"no valid HTTP/HTTPS URLs found in: {path}")

    return unique_targets


def get_targets(args, parser):
    if args.url and args.list:
        parser.error("arguments -u/--url and -l/--list cannot be used together")

    if args.url:
        url = args.url.strip()

        if not url:
            parser.error("target URL cannot be empty")

        if not is_valid_url(url):
            parser.error(f"invalid target URL: {url}\ntarget must be a full HTTP/HTTPS URL")

        return [url]

    if args.list:
        try:
            return load_targets(args.list)
        except ValueError as err:
            parser.error(str(err))

    parser.error("the following argument is required: -u/--url or -l/--list")


def build_config(args, headers):
    return {
        "headers": headers,
        "method": args.method,
        "data": args.data,
        "timeout": args.timeout,
        "workers": args.thread,
        "mode": args.mode,
        "output": args.output or args.json,
        "json": bool(args.json),
    }


def main():
    try:
        parser = build_flags()

        # No arguments
        if len(sys.argv) == 1:
            print(display.logo())
            print()
            parser.print_help()
            return

        args = parser.parse_args()

        # Version
        if args.version:
            show_version()
            return

        # Show details
        if args.rule:
            for rule_id in args.rule:
                show_id_details(rule_id)
            return

        # Targets
        targets = get_targets(args, parser)

        # Headers
        headers = {}

        if args.header:
            if ":" not in args.header:
                parser.error("invalid header format. Use: 'Header: value'")

            name, value = args.header.split(":", 1)
            name = name.strip()
            value = value.strip()

            if not name:
                parser.error("header name cannot be empty")

            headers[name] = value

        # Configuration
        config = build_config(args=args, headers=headers)

        # Display logo
        print(display.logo())

        # Scan
        stat = cors_run(urls=targets, config=config, on_target_done=display.findings)

        # Verbose
        if args.verbose:
            show_verbose(stat.results)

        # Summary
        display.summary(stat)

        # Reporter
        if args.output and args.json:
            parser.error("-o/--output and -j/--json cannot be used together")

        if args.output:
            try:
                reporter.write(findings=stat.findings, path=args.output, json_output=False)
            except OSError as err:
                parser.error(f"unable to write output: {err}")

        elif args.json:
            try:
                reporter.write(findings=stat.findings, path=args.json, json_output=True)
            except OSError as err:
                parser.error(f"unable to write output: {err}")

    except KeyboardInterrupt:
        print(
            f"\n{Fore.YELLOW}Scan interrupted by user..."
            f"{Style.RESET_ALL}"
        )
        raise SystemExit(130)


if __name__ == "__main__":
    main()