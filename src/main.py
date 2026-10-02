import argparse
import ipaddress
import re
from pathlib import Path

from scanner import run_nmap_scan
from parser import parse_nmap_xml, save_scan_as_json


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_JSON = BASE_DIR / "scans" / "scan.json"


def is_valid_domain(domain: str) -> bool:
    """
    Validate a basic domain name format.
    """

    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return bool(domain_pattern.fullmatch(domain))


def validate_target(target: str) -> str:
    """
    Validate that the target is either a valid IP address
    or a valid domain name.
    """

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if is_valid_domain(target):
        return target

    raise ValueError(
        f"Invalid target: '{target}'. "
        "Use a valid IP address or domain."
    )


def build_cli():
    """
    Build the Urkunina Scan command-line interface.
    """

    parser = argparse.ArgumentParser(
        prog="urkunina-scan",
        description="Run a basic Nmap service scan against an authorized target.",
    )

    parser.add_argument(
        "target",
        help="Authorized IP address or domain to scan.",
    )

    return parser


def main():
    """
    Main Urkunina Scan workflow.

    Flow:
    1. Read target from CLI.
    2. Validate the target.
    3. Run Nmap.
    4. Parse Nmap XML.
    5. Add original target context.
    6. Save normalized output as JSON.
    """

    cli = build_cli()
    args = cli.parse_args()

    try:
        target = validate_target(args.target)

        print(f"[+] Starting Urkunina Scan against: {target}")

        xml_file = run_nmap_scan(target)

        scan_result = parse_nmap_xml(xml_file)

        scan_result = {
            "target": target,
            **scan_result,
        }
        save_scan_as_json(
            scan_result,
            OUTPUT_JSON,
        )

        print("[+] Scan completed successfully")
        print(f"[+] JSON saved to: {OUTPUT_JSON}")

    except ValueError as error:
        print(f"[-] Validation error: {error}")

    except RuntimeError as error:
        print(f"[-] Scan error: {error}")

    except Exception as error:
        print(f"[-] Unexpected error: {error}")


if __name__ == "__main__":
    main()