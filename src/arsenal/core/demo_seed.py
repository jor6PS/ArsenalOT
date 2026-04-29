from __future__ import annotations

import base64
import json
import shutil
import sqlite3
import struct
import zlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEMO_ORGANIZATION = "ATLAS"
LEGACY_DEMO_ORGANIZATIONS = ("DEMO_PLANTA_ATLAS",)
DEMO_DESCRIPTION = (
    "Organización de demostración con entornos IT, DMZ industrial y OT. "
    "Incluye escaneos activos, importaciones, descubrimiento industrial, "
    "capturas web, credenciales y rutas de ataque multi-salto."
)


def seed_demo_organization(storage, reset: bool = True) -> Dict[str, Any]:
    """Carga una organización demo rica y repetible para enseñar la aplicación."""
    organization = DEMO_ORGANIZATION.upper()

    if reset:
        _reset_demo_organization(storage, organization)
        for legacy_organization in LEGACY_DEMO_ORGANIZATIONS:
            if legacy_organization != organization:
                _reset_demo_organization(storage, legacy_organization)

    storage.create_organization(organization, DEMO_DESCRIPTION)
    network_ids = _seed_architecture(storage, organization)
    scan_ids = _seed_scans(storage, organization)
    _seed_network_devices(storage, organization, network_ids)
    _restore_description(storage, organization)

    return {
        "organization": organization,
        "description": DEMO_DESCRIPTION,
        "scans": len(scan_ids),
        "scan_ids": scan_ids,
        "networks": len(network_ids),
        "hosts": _count_organization_hosts(storage, organization),
        "services": _count_organization_services(storage, organization),
        "vulnerabilities": _count_organization_vulnerabilities(storage, organization),
    }


def _reset_demo_organization(storage, organization: str) -> None:
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    scan_ids = [
        row[0]
        for row in cursor.execute(
            "SELECT id FROM scans WHERE organization_name = ?", (organization,)
        ).fetchall()
    ]
    host_ids: List[int] = []
    if scan_ids:
        placeholders = ",".join("?" for _ in scan_ids)
        host_ids = [
            row[0]
            for row in cursor.execute(
                f"SELECT DISTINCT host_id FROM scan_results WHERE scan_id IN ({placeholders})",
                scan_ids,
            ).fetchall()
        ]

    cursor.execute("DELETE FROM organizations WHERE name = ?", (organization,))
    for host_id in host_ids:
        remaining = cursor.execute(
            "SELECT COUNT(*) FROM scan_results WHERE host_id = ?", (host_id,)
        ).fetchone()[0]
        if remaining == 0:
            cursor.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    cursor.execute(
        "DELETE FROM hosts WHERE id NOT IN (SELECT DISTINCT host_id FROM scan_results WHERE host_id IS NOT NULL)"
    )
    conn.commit()
    conn.close()

    org_dir = Path(storage.results_root) / organization
    if org_dir.exists():
        shutil.rmtree(org_dir, ignore_errors=True)


def _seed_architecture(storage, organization: str) -> Dict[str, int]:
    networks = [
        ("CORP_SERVICES", "10.10.10.0/24", "IT Corporativo", 5),
        ("CORP_USERS", "10.10.20.0/24", "IT Corporativo", 5),
        ("VPN_ADMIN", "10.10.30.0/24", "IT Corporativo", 5),
        ("INDUSTRIAL_DMZ", "10.20.10.0/24", "DMZ Industrial", 3.5),
        ("HISTORIAN_DMZ", "10.20.20.0/24", "DMZ Industrial", 3.5),
        ("OT_SUPERVISION_A", "10.30.20.0/24", "Línea A Mezclado", 2),
        ("OT_CONTROL_A", "10.30.10.0/24", "Línea A Mezclado", 1),
        ("OT_SUPERVISION_B", "10.40.20.0/24", "Línea B Envasado", 2),
        ("OT_CONTROL_B", "10.40.10.0/24", "Línea B Envasado", 1),
        ("SAFETY_ISLAND", "10.50.10.0/24", "Seguridad Funcional", 0),
        ("SHADOW_VENDOR", "172.22.5.0/24", "Redes no inventariadas", 2),
    ]
    network_ids: Dict[str, int] = {}
    for name, cidr, system, level in networks:
        network_ids[name] = storage.add_network(
            organization, name, cidr, system_name=system, purdue_level=level
        )

    critical_devices = [
        ("DC_CORP_01", "10.10.10.10", "Controlador de dominio visible desde varios orígenes", "IT Corporativo"),
        ("JUMPBOX_OT", "10.20.10.25", "Pivote administrativo hacia OT", "DMZ Industrial"),
        ("HISTORIAN_CORE", "10.20.20.10", "Historiador con datos de proceso y doble visibilidad", "DMZ Industrial"),
        ("HMI_MEZCLADO_01", "10.30.20.15", "HMI con acceso a PLCs de línea A", "Línea A Mezclado"),
        ("ENG_WS_LINEA_A", "10.30.10.50", "Estación de ingeniería con TIA Portal y credenciales locales", "Línea A Mezclado"),
        ("PLC_LINEA_A_01", "10.30.10.21", "PLC crítico de dosificación vulnerable a escritura Modbus", "Línea A Mezclado"),
        ("SIS_SAFETY_01", "10.50.10.5", "Controlador de seguridad alcanzable desde HMI", "Seguridad Funcional"),
        ("VENDOR_AP_SHADOW", "172.22.5.20", "Dispositivo de proveedor descubierto fuera de alcance declarado", "Redes no inventariadas"),
    ]
    for name, ips, reason, system in critical_devices:
        storage.add_critical_device(organization, name, ips, reason, system_name=system)

    return network_ids


def _seed_network_devices(storage, organization: str, network_ids: Dict[str, int]) -> None:
    fw_dmz = storage.add_network_device(
        organization,
        "FW-CORE-DMZ",
        "firewall",
        system_name="DMZ Industrial",
        management_ip="10.20.10.1",
        accessible_network_ids=[
            network_ids["CORP_SERVICES"],
            network_ids["INDUSTRIAL_DMZ"],
            network_ids["HISTORIAN_DMZ"],
        ],
        origin_locations=["CORP-LAPTOP", "VPN-PENTEST"],
        notes="Permite administración filtrada desde IT hacia la DMZ industrial.",
    )
    router_a = storage.add_network_device(
        organization,
        "RTR-OT-LINEA-A",
        "router",
        system_name="Línea A Mezclado",
        management_ip="10.30.20.1",
        accessible_network_ids=[
            network_ids["INDUSTRIAL_DMZ"],
            network_ids["OT_SUPERVISION_A"],
            network_ids["OT_CONTROL_A"],
            network_ids["SAFETY_ISLAND"],
        ],
        origin_locations=["JUMPBOX-OT", "HMI-LINEA-A"],
        connected_device_ids=[fw_dmz],
        notes="Ruta que provoca varios saltos en el attack path hasta PLC/SIS.",
    )
    storage.add_network_device(
        organization,
        "SW-PLC-A-RING",
        "switch",
        system_name="Línea A Mezclado",
        management_ip="10.30.10.2",
        accessible_network_ids=[network_ids["OT_CONTROL_A"]],
        origin_locations=["ENGINEERING-WS-A"],
        connected_device_ids=[router_a],
        notes="Anillo de control con S7 y Modbus expuestos.",
    )
    storage.add_network_device(
        organization,
        "RTR-VENDOR-SHADOW",
        "router",
        system_name="Redes no inventariadas",
        management_ip="172.22.5.1",
        accessible_network_ids=[network_ids["SHADOW_VENDOR"], network_ids["OT_SUPERVISION_B"]],
        origin_locations=["VENDOR-VPN"],
        notes="Ruta no documentada encontrada durante una importación Nmap.",
    )


def _seed_scans(storage, organization: str) -> List[int]:
    base = datetime.now() - timedelta(days=18, hours=4)
    plans = [
        {
            "location": "CORP-LAPTOP",
            "scan_type": "nmap_active",
            "target_range": "10.10.10.0/24 10.20.10.0/24 10.30.20.0/24",
            "myip": "10.10.10.55",
            "started": base,
            "command": "nmap -sS -sV -O --top-ports 200 10.10.10.0/24 10.20.10.0/24 10.30.20.0/24",
            "hosts": [
                host("10.10.10.10", "DC-CORP-01", "Microsoft", "Windows Server 2019", [svc(53, "domain", "Microsoft DNS", "10.0"), svc(88, "kerberos", "Microsoft Kerberos"), svc(389, "ldap", "Active Directory LDAP"), svc(445, "microsoft-ds", "Windows SMB", "SMBv1 compatible")]),
                host("10.10.10.25", "FILE-BACKUP-01", "Dell", "Windows Server 2016", [svc(445, "microsoft-ds", "Windows SMB"), svc(3389, "ms-wbt-server", "RDP", "NLA disabled")]),
                host("10.10.10.55", "CORP-LAPTOP", "Lenovo", "Windows 11", [], "host_discovery"),
                host("10.20.10.25", "JUMPBOX-OT", "VMware", "Windows Server 2019", [svc(3389, "ms-wbt-server", "RDP"), svc(5985, "winrm", "Microsoft HTTPAPI")]),
                host("10.20.10.40", "WSUS-OT-DMZ", "Microsoft", "Windows Server 2016", [svc(8530, "http", "Microsoft WSUS"), svc(445, "microsoft-ds", "Windows SMB")]),
                host("10.30.20.15", "HMI-MEZCLADO-01", "Siemens", "Windows 10 IoT", [svc(80, "http", "WinCC Runtime", "7.5"), svc(5900, "vnc", "RealVNC", "5.3")]),
            ],
            "vulnerabilities": [
                vuln("10.10.10.10", 445, "ARS-DEMO-SMB-001", "SMB signing not required", "high", 8.1, "El controlador de dominio acepta sesiones SMB sin firma obligatoria."),
                vuln("10.10.10.25", 3389, "ARS-DEMO-RDP-001", "RDP sin NLA", "medium", 6.5, "El servidor permite negociación RDP sin Network Level Authentication."),
            ],
        },
        {
            "location": "VPN-PENTEST",
            "scan_type": "netexec_smb_ldap",
            "target_range": "10.10.10.0/24 10.20.10.0/24 10.20.20.0/24 10.40.20.0/24",
            "myip": "10.10.30.40",
            "started": base + timedelta(days=2, hours=3),
            "command": "nxc smb 10.10.10.0/24 10.20.10.0/24 10.20.20.0/24 10.40.20.0/24 --shares --pass-pol",
            "hosts": [
                host("10.10.10.10", "DC-CORP-01", "Microsoft", "Windows Server 2019", [svc(445, "microsoft-ds", "Windows SMB"), svc(389, "ldap", "Active Directory LDAP")], "netexec"),
                host("10.20.10.25", "JUMPBOX-OT", "VMware", "Windows Server 2019", [svc(445, "microsoft-ds", "Windows SMB"), svc(5985, "winrm", "Microsoft HTTPAPI")], "netexec"),
                host("10.20.20.10", "HISTORIAN-CORE", "AVEVA", "Windows Server 2019", [svc(1433, "ms-sql-s", "Microsoft SQL Server", "2017"), svc(443, "https", "AVEVA Historian Portal", "2020 R2")], "netexec"),
                host("10.40.20.12", "HMI-ENVASADO-01", "Rockwell", "Windows 10 IoT", [svc(80, "http", "FactoryTalk View"), svc(44818, "ethernetip", "EtherNet/IP")], "nmap_ports"),
            ],
            "credentials": [
                ("DEMO", "svc_backup", "Summer2026!", "password", "smb", "10.10.10.25"),
                ("DEMO", "ot_engineer", "AAD3B435B51404EEAAD3B435B51404EE:5F4DCC3B5AA765D61D8327DEB882CF99", "ntlm", "smb", "10.20.10.25"),
            ],
            "vulnerabilities": [
                vuln("10.20.20.10", 1433, "ARS-DEMO-SQL-001", "SQL Server con autenticación mixta expuesta", "high", 7.8, "El historiador acepta autenticación SQL además de dominio."),
            ],
        },
        {
            "location": "JUMPBOX-OT",
            "scan_type": "nmap_ot_supervision",
            "target_range": "10.20.20.0/24 10.30.20.0/24 10.40.20.0/24",
            "myip": "10.20.10.25",
            "started": base + timedelta(days=5, hours=2),
            "command": "nmap -sT -sV -p 80,443,445,3389,4840,8080,5900 10.20.20.0/24 10.30.20.0/24 10.40.20.0/24",
            "screenshots": True,
            "hosts": [
                host("10.20.20.10", "HISTORIAN-CORE", "AVEVA", "Windows Server 2019", [svc(443, "https", "AVEVA Historian Portal", "2020 R2"), svc(4840, "opcua", "OPC UA Server", "1.04")]),
                host("10.30.20.15", "HMI-MEZCLADO-01", "Siemens", "Windows 10 IoT", [svc(80, "http", "WinCC Runtime", "7.5"), svc(5900, "vnc", "RealVNC", "5.3"), svc(4840, "opcua", "Siemens OPC UA")]),
                host("10.30.20.22", "SCADA-REPORT-A", "Ignition", "Linux", [svc(8088, "http", "Ignition Gateway", "8.1.25"), svc(8043, "https", "Ignition Gateway")]),
                host("10.40.20.12", "HMI-ENVASADO-01", "Rockwell", "Windows 10 IoT", [svc(80, "http", "FactoryTalk View"), svc(44818, "ethernetip", "EtherNet/IP")]),
            ],
            "vulnerabilities": [
                vuln("10.30.20.15", 5900, "ARS-DEMO-VNC-001", "VNC sin cifrado fuerte", "high", 7.4, "El HMI expone VNC con autenticación débil y sin cifrado robusto."),
                vuln("10.30.20.22", 8088, "ARS-DEMO-IGN-001", "Ignition Gateway con consola administrativa expuesta", "medium", 6.4, "La consola permite enumeración de versión y módulos instalados."),
            ],
        },
        {
            "location": "HMI-LINEA-A",
            "scan_type": "industrial_discovery",
            "target_range": "10.30.10.0/24 10.50.10.0/24",
            "myip": "10.30.20.15",
            "started": base + timedelta(days=8, minutes=20),
            "command": "nmap -sT -sV -p 102,502,44818,20000 10.30.10.0/24 10.50.10.0/24 --script modbus-discover,s7-info,enip-info",
            "hosts": [
                host("10.30.10.21", "PLC-LINEA-A-01", "Siemens", "S7-1500", [svc(102, "iso-tsap", "Siemens S7", "3.1"), svc(502, "modbus", "Modbus TCP")], "nmap_ports"),
                host("10.30.10.22", "PLC-LINEA-A-02", "Schneider Electric", "M340", [svc(502, "modbus", "Schneider Modbus"), svc(80, "http", "Schneider WebServer")], "nmap_ports"),
                host("10.30.10.50", "ENG-WS-LINEA-A", "Siemens", "Windows 10 Engineering", [svc(445, "microsoft-ds", "Windows SMB"), svc(3389, "ms-wbt-server", "RDP")], "nmap_ports"),
                host("10.50.10.5", "SIS-SAFETY-01", "HIMA", "HIMax", [svc(502, "modbus", "Safety Modbus"), svc(20000, "dnp3", "DNP3")], "nmap_ports"),
            ],
            "vulnerabilities": [
                vuln("10.30.10.21", 502, "ARS-DEMO-MODBUS-001", "Modbus permite escritura sin autenticación", "critical", 9.6, "El PLC crítico acepta funciones de escritura desde el segmento HMI."),
                vuln("10.50.10.5", 502, "ARS-DEMO-SIS-001", "Controlador de seguridad alcanzable desde red no Safety", "critical", 9.1, "El SIS aparece en la ruta de visibilidad desde un HMI de supervisión."),
            ],
        },
        {
            "location": "ENGINEERING-WS-A",
            "scan_type": "specific_capture",
            "target_range": "10.30.10.21 10.30.10.22 10.30.10.50",
            "myip": "10.30.10.50",
            "started": base + timedelta(days=11, hours=6),
            "command": "specific web+industrial enrichment on engineering station",
            "screenshots": True,
            "hosts": [
                host("10.30.10.21", "PLC-LINEA-A-01", "Siemens", "S7-1500", [svc(102, "iso-tsap", "Siemens S7"), svc(80, "http", "PLC Diagnostics Portal")], "specific_capture"),
                host("10.30.10.22", "PLC-LINEA-A-02", "Schneider Electric", "M340", [svc(502, "modbus", "Schneider Modbus"), svc(80, "http", "PLC Web Diagnostics")], "specific_capture"),
                host("10.30.10.50", "ENG-WS-LINEA-A", "Siemens", "Windows 10 Engineering", [svc(445, "microsoft-ds", "Windows SMB"), svc(5985, "winrm", "Microsoft HTTPAPI")], "specific_capture"),
            ],
            "credentials": [
                ("LOCAL", "engineer", "Welcome1!", "password", "winrm", "10.30.10.50"),
                ("PLC", "admin", "admin", "password", "http", "10.30.10.21"),
            ],
            "vulnerabilities": [
                vuln("10.30.10.21", 80, "ARS-DEMO-PLCWEB-001", "Portal PLC con credenciales por defecto", "critical", 9.0, "El portal de diagnóstico acepta admin/admin."),
            ],
        },
        {
            "location": "VENDOR-VPN",
            "scan_type": "nmap_import_shadow",
            "target_range": "172.22.5.0/24 10.40.20.0/24",
            "myip": "172.22.5.50",
            "started": base + timedelta(days=14, hours=1),
            "command": "imported vendor scan: nmap -oX vendor-shadow.xml 172.22.5.0/24 10.40.20.0/24",
            "hosts": [
                host("172.22.5.20", "VENDOR-AP-SHADOW", "Ubiquiti", "airOS", [svc(80, "http", "airOS"), svc(22, "ssh", "Dropbear SSH")], "nmap_import"),
                host("172.22.5.21", "VENDOR-NAS", "QNAP", "QTS", [svc(8080, "http", "QNAP Admin"), svc(445, "microsoft-ds", "Samba")], "nmap_import"),
                host("10.40.20.12", "HMI-ENVASADO-01", "Rockwell", "Windows 10 IoT", [svc(80, "http", "FactoryTalk View"), svc(44818, "ethernetip", "EtherNet/IP")], "nmap_import"),
            ],
            "vulnerabilities": [
                vuln("172.22.5.20", 80, "ARS-DEMO-VENDOR-001", "Dispositivo de proveedor no inventariado", "medium", 6.0, "La red del proveedor aparece conectada a supervisión OT sin estar declarada inicialmente."),
            ],
        },
    ]

    scan_ids: List[int] = []
    for index, plan in enumerate(plans):
        scan_id = storage.start_scan(
            organization=organization,
            location=plan["location"],
            scan_type=plan["scan_type"],
            target_range=plan["target_range"],
            interface="demo0",
            myip=plan["myip"],
            nmap_command=plan["command"],
            created_by="demo-seed",
            enable_version_detection=True,
            enable_vulnerability_scan=bool(plan.get("vulnerabilities")),
            enable_screenshots=bool(plan.get("screenshots")),
            enable_source_code=bool(plan.get("screenshots")),
            scan_mode="specific" if plan["scan_type"] == "specific_capture" else "active",
            started_at=plan["started"],
        )
        rows = _flatten_host_rows(plan["hosts"], plan["started"])
        storage.save_host_results_bulk(scan_id, rows)
        for vulnerability in plan.get("vulnerabilities", []):
            storage.save_vulnerability(scan_id, *vulnerability)
        for credential in plan.get("credentials", []):
            _insert_credential(storage, organization, scan_id, credential)
        if plan.get("screenshots"):
            _seed_web_evidence(storage, organization, plan["location"], scan_id, plan["hosts"], index)
        storage.complete_scan(
            scan_id,
            completed_at=plan["started"] + timedelta(minutes=17 + index * 3),
        )
        scan_ids.append(scan_id)

    return scan_ids


def host(
    ip: str,
    hostname: str,
    vendor: str,
    os_name: str,
    services: List[Dict[str, Any]],
    discovery_method: str = "nmap_ports",
) -> Dict[str, Any]:
    return {
        "ip": ip,
        "hostname": hostname,
        "vendor": vendor,
        "os": os_name,
        "services": services,
        "discovery_method": discovery_method,
    }


def svc(port: int, name: str, product: str, version: str = "") -> Dict[str, Any]:
    scripts = {}
    if name in {"modbus", "iso-tsap", "ethernetip", "opcua", "dnp3"}:
        scripts["ot-protocol-info"] = f"{product} {version}".strip()
    if name in {"http", "https"}:
        scripts["http-title"] = product
    return {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "service_data": {
            "name": name,
            "product": product,
            "version": version,
            "extrainfo": "demo generated evidence",
            "conf": 10,
            "scripts": scripts,
        },
    }


def vuln(
    ip: str,
    port: int,
    vulnerability_id: str,
    name: str,
    severity: str,
    score: float,
    description: str,
) -> Tuple[str, int, str, Dict[str, Any]]:
    return (
        ip,
        port,
        "tcp",
        {
            "vulnerability_id": vulnerability_id,
            "vulnerability_name": name,
            "severity": severity,
            "description": description,
            "cve_id": None,
            "cvss_score": score,
            "script_source": "arsenalot-demo",
            "script_output": description,
        },
    )


def _flatten_host_rows(hosts: Iterable[Dict[str, Any]], discovered_at: datetime) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in hosts:
        host_data = {
            "hostnames": [item["hostname"]],
            "mac_address": _fake_mac(item["ip"]),
            "vendor": item["vendor"],
            "os": [{"name": item["os"], "accuracy": "95"}],
            "host_scripts": {
                "demo-note": f"Activo demo {item['hostname']} descubierto por {item['discovery_method']}"
            },
        }
        rows.append(
            {
                "host_ip": item["ip"],
                "hostname": item["hostname"],
                "host_data": host_data,
                "discovery_method": item["discovery_method"],
                "discovered_at": discovered_at,
            }
        )
        for service in item["services"]:
            service_row = {
                "host_ip": item["ip"],
                "hostname": item["hostname"],
                "host_data": host_data,
                "discovery_method": item["discovery_method"],
                "discovered_at": discovered_at,
            }
            service_row.update(service)
            rows.append(service_row)
    return rows


def _seed_web_evidence(
    storage,
    organization: str,
    location: str,
    scan_id: int,
    hosts: Iterable[Dict[str, Any]],
    palette_index: int,
) -> None:
    scan_dir = storage.get_scan_directory(organization, location, scan_id)
    img_dir = scan_dir / "evidence" / "img"
    source_dir = scan_dir / "evidence" / "source"
    img_dir.mkdir(parents=True, exist_ok=True)
    source_dir.mkdir(parents=True, exist_ok=True)

    web_ports = {"http", "https"}
    colors = [(26, 115, 232), (14, 165, 233), (16, 185, 129), (245, 158, 11), (239, 68, 68)]
    for host_item in hosts:
        for service in host_item["services"]:
            service_data = service["service_data"]
            if service_data.get("name") not in web_ports:
                continue
            port = service["port"]
            title = f"{host_item['hostname']}:{port} · {service_data.get('product')}"
            accent = colors[(palette_index + port) % len(colors)]
            image_path = img_dir / f"{host_item['ip']}_{port}.png"
            source_path = source_dir / f"{host_item['ip']}_{port}.html"
            _write_demo_png(image_path, title, accent)
            html = _demo_html_source(title, host_item, service_data)
            source_path.write_text(html, encoding="utf-8")
            encoded = base64.b64encode(image_path.read_bytes()).decode("ascii")
            storage.save_enrichment(scan_id, host_item["ip"], port, "tcp", "Screenshot", encoded, str(image_path))
            storage.save_enrichment(scan_id, host_item["ip"], port, "tcp", "Websource", html, str(source_path))


def _write_demo_png(path: Path, title: str, accent: Tuple[int, int, int]) -> None:
    width, height = 980, 560
    try:
        from PIL import Image, ImageDraw, ImageFont

        image = Image.new("RGB", (width, height), (15, 23, 42))
        draw = ImageDraw.Draw(image)
        font_title = ImageFont.load_default()
        draw.rounded_rectangle((36, 34, 944, 526), radius=24, fill=(248, 250, 252))
        draw.rectangle((36, 34, 944, 110), fill=accent)
        draw.text((64, 60), title, fill=(255, 255, 255), font=font_title)
        for idx, label in enumerate(["Estado: ONLINE", "Rol: DEMO OT", "Evidencia: CAPTURA", "Riesgo: revisar"]):
            top = 150 + idx * 72
            draw.rounded_rectangle((76, top, 902, top + 48), radius=12, fill=(226, 232, 240))
            draw.text((104, top + 16), label, fill=(30, 41, 59), font=font_title)
        image.save(path)
        return
    except Exception:
        pass

    rows = []
    background = (248, 250, 252)
    dark = (15, 23, 42)
    for y in range(height):
        row = bytearray()
        for x in range(width):
            if y < 78:
                pixel = accent
            elif 120 < y < 500 and 70 < x < 910:
                stripe = ((y - 120) // 70) % 2 == 0
                pixel = (226, 232, 240) if stripe else (241, 245, 249)
            elif x < 24 or y < 24 or x > width - 24 or y > height - 24:
                pixel = dark
            else:
                pixel = background
            row.extend(pixel)
        rows.append(b"\x00" + bytes(row))
    raw = b"".join(rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(png)


def _demo_html_source(title: str, host_item: Dict[str, Any], service_data: Dict[str, Any]) -> str:
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
</head>
<body>
  <h1>{title}</h1>
  <p>Activo demo: {host_item['hostname']} ({host_item['ip']})</p>
  <p>Producto: {service_data.get('product')} {service_data.get('version', '')}</p>
  <form>
    <label>Usuario</label><input name="username" value="admin">
    <label>Password</label><input name="password" type="password" value="admin">
  </form>
</body>
</html>
"""


def _insert_credential(storage, organization: str, scan_id: int, credential: Tuple[str, str, str, str, str, str]) -> None:
    domain, username, password, credtype, protocol, source_host = credential
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        INSERT OR IGNORE INTO credentials
            (scan_id, organization_name, domain, username, password, credtype, source_protocol, source_host_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_id, organization, domain, username, password, credtype, protocol, source_host),
    )
    conn.commit()
    conn.close()


def _restore_description(storage, organization: str) -> None:
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "UPDATE organizations SET description = ? WHERE name = ?",
        (DEMO_DESCRIPTION, organization),
    )
    conn.commit()
    conn.close()


def _count_organization_hosts(storage, organization: str) -> int:
    query = """
        SELECT COUNT(DISTINCT sr.host_id)
        FROM scan_results sr
        JOIN scans s ON s.id = sr.scan_id
        WHERE s.organization_name = ?
    """
    return _scalar_count(storage, query, organization)


def _count_organization_services(storage, organization: str) -> int:
    query = """
        SELECT COUNT(*)
        FROM scan_results sr
        JOIN scans s ON s.id = sr.scan_id
        WHERE s.organization_name = ? AND sr.port IS NOT NULL
    """
    return _scalar_count(storage, query, organization)


def _count_organization_vulnerabilities(storage, organization: str) -> int:
    query = """
        SELECT COUNT(*)
        FROM vulnerabilities v
        JOIN scan_results sr ON sr.id = v.scan_result_id
        JOIN scans s ON s.id = sr.scan_id
        WHERE s.organization_name = ?
    """
    return _scalar_count(storage, query, organization)


def _scalar_count(storage, query: str, organization: str) -> int:
    conn = sqlite3.connect(str(storage.db_path), timeout=30.0)
    count = conn.execute(query, (organization,)).fetchone()[0]
    conn.close()
    return int(count or 0)


def _fake_mac(ip: str) -> str:
    octets = [int(part) for part in ip.split(".")]
    return "02:42:%02x:%02x:%02x:%02x" % tuple(octets)
