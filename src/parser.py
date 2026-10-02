import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_nmap_xml(xml_file: Path) -> dict[str, Any]:
    """
    Parse an Nmap XML file and normalize relevant scan information.

    Extracts:
    - scanner metadata
    - host information
    - scan summary
    - ports and detected services
    - grouped extra ports such as closed ports

    Parameters
    ----------
    xml_file : Path
        Path to the Nmap XML output file.

    Returns
    -------
    dict[str, Any]
        Normalized scan data ready to be exported as JSON.
    """

    tree = ET.parse(xml_file)
    root = tree.getroot()

    scanner_name = root.get("scanner")
    scanner_version = root.get("version")
    scan_started = root.get("startstr")

    host = root.find("host")

    if host is None:
        raise ValueError("No host information found in the Nmap XML file.")

    address_element = host.find("address")
    status_element = host.find("status")

    ip = (
        address_element.get("addr")
        if address_element is not None
        else None
    )

    status = (
        status_element.get("state")
        if status_element is not None
        else None
    )

    ports_element = host.find("ports")
    ports_data = []

    open_ports = 0
    filtered_ports = 0
    closed_ports = 0

    if ports_element is not None:
        # Nmap groups large sets of ports with the same state
        # inside <extraports>, for example:
        # <extraports state="closed" count="996">
        extraports_element = ports_element.find("extraports")

        if extraports_element is not None:
            extraports_state = extraports_element.get("state")
            extraports_count = extraports_element.get("count")

            if extraports_count is not None:
                count = int(extraports_count)

                if extraports_state == "closed":
                    closed_ports += count

                elif extraports_state == "filtered":
                    filtered_ports += count

                elif extraports_state == "open":
                    open_ports += count

        # Ports explicitly reported by Nmap.
        for port in ports_element.findall("port"):
            port_id = port.get("portid")
            protocol = port.get("protocol")

            state_element = port.find("state")

            state = (
                state_element.get("state")
                if state_element is not None
                else None
            )

            service_element = port.find("service")

            service = (
                service_element.get("name")
                if service_element is not None
                else None
            )

            product = (
                service_element.get("product")
                if service_element is not None
                else None
            )

            version = (
                service_element.get("version")
                if service_element is not None
                else None
            )

            if state == "open":
                open_ports += 1

            elif state == "filtered":
                filtered_ports += 1

            elif state == "closed":
                closed_ports += 1

            ports_data.append(
                {
                    "port": int(port_id) if port_id else None,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                }
            )

    total_ports_scanned = (
        open_ports
        + filtered_ports
        + closed_ports
    )

    return {
        "metadata": {
            "scanner": scanner_name,
            "scanner_version": scanner_version,
            "scan_started": scan_started,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        },
        "host": {
            "ip": ip,
            "status": status,
        },
        "summary": {
            "ports_reported": len(ports_data),
            "open": open_ports,
            "filtered": filtered_ports,
            "closed": closed_ports,
            "total_ports_scanned": total_ports_scanned,
        },
        "ports": ports_data,
    }


def save_scan_as_json(
    scan_result: dict[str, Any],
    output_file: Path,
) -> None:
    """
    Save normalized scan data as formatted JSON.
    """

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(
            scan_result,
            file,
            indent=4,
        )


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent

    xml_file = base_dir / "scans" / "scan.xml"
    json_file = base_dir / "scans" / "scan.json"

    result = parse_nmap_xml(xml_file)

    save_scan_as_json(
        result,
        json_file,
    )

    print(json.dumps(result, indent=4))
    print(f"\nJSON saved to: {json_file}")