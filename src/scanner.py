import shutil
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SCANS_DIR = BASE_DIR / "scans"


def check_nmap_installed() -> None:
    """
    Verify that Nmap is available in the system PATH.

    Raises
    ------
    RuntimeError
        If Nmap is not installed or cannot be found.
    """

    if shutil.which("nmap") is None:
        raise RuntimeError(
            "Nmap is not installed or is not available in PATH."
        )


def run_nmap_scan(target: str) -> Path:
    """
    Run an Nmap service/version scan against an authorized target.

    Parameters
    ----------
    target : str
        IP address or domain to scan.

    Returns
    -------
    Path
        Path to the generated XML file.

    Raises
    ------
    RuntimeError
        If Nmap is missing, times out, or fails.
    """

    check_nmap_installed()

    SCANS_DIR.mkdir(exist_ok=True)

    output_file = SCANS_DIR / "scan.xml"

    command = [
        "nmap",
        "-sV",
        "-oX",
        str(output_file),
        target,
    ]

    print(f"Running scan against: {target}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Nmap scan timed out after 120 seconds."
        )

    except OSError as error:
        raise RuntimeError(
            f"Failed to execute Nmap: {error}"
        )

    if result.returncode != 0:
        error_message = result.stderr.strip()

        if not error_message:
            error_message = "Unknown Nmap error."

        raise RuntimeError(
            f"Nmap scan failed: {error_message}"
        )

    if not output_file.exists():
        raise RuntimeError(
            "Nmap finished but no XML output file was generated."
        )

    print(f"Scan completed. XML saved to: {output_file}")

    return output_file


if __name__ == "__main__":
    run_nmap_scan("scanme.nmap.org")