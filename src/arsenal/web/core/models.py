from pydantic import BaseModel
from typing import List, Optional

class ScanConfig(BaseModel):
    organization: str
    location: str
    target_range: Optional[str] = "0.0.0.0/0"  # Opcional, por defecto para pasivo
    interface: str = ""
    myip: Optional[str] = None
    scan_mode: str = "active"  # active o passive
    # Opciones para escaneos activos
    host_discovery: bool = False
    nmap: bool = False
    nmap_icmp: bool = False
    nmap_speed: str = "normal"  # rapido, normal, lento
    nmap_versions: bool = False
    nmap_vulns: bool = False
    nmap_ot_ports: bool = False
    nmap_it_ports: bool = False
    custom_ports: Optional[str] = None
    custom_ping_command: Optional[str] = None
    custom_nmap_command: Optional[str] = None
    custom_host_discovery_command: Optional[str] = None
    ioxid: bool = False
    screenshots: bool = False
    source_code: bool = False
    # Opciones para escaneos pasivos
    pcap_filter: Optional[str] = None  # Filtro BPF para tshark (ej: "tcp port 80")

class Neo4jConfig(BaseModel):
    ip: str
    username: str
    password: str
    organization: Optional[str] = None
    location: Optional[str] = None

class NetworkCreateRequest(BaseModel):
    organization: str
    network_name: str
    network_range: str
    system_name: Optional[str] = None
    purdue_level: Optional[int] = None

class NetworkUpdateRequest(BaseModel):
    network_name: str
    network_range: str
    system_name: Optional[str] = None
    purdue_level: Optional[int] = None

class CriticalDeviceRequest(BaseModel):
    organization: str
    system_name: Optional[str] = None
    name: str
    ips: str         # IPs separadas por comas: "192.168.1.1, 10.0.0.5"
    reason: str

class CriticalDeviceUpdateRequest(BaseModel):
    system_name: Optional[str] = None
    name: str
    ips: str
    reason: str

class NetworkDeviceRequest(BaseModel):
    organization: str
    system_name: Optional[str] = None
    name: str
    device_type: str
    management_ip: Optional[str] = None
    accessible_network_ids: List[int] = []
    origin_locations: List[str] = []
    connected_device_ids: List[int] = []
    notes: Optional[str] = None

class NetworkDeviceUpdateRequest(BaseModel):
    system_name: Optional[str] = None
    name: str
    device_type: str
    management_ip: Optional[str] = None
    accessible_network_ids: List[int] = []
    origin_locations: List[str] = []
    connected_device_ids: List[int] = []
    notes: Optional[str] = None
