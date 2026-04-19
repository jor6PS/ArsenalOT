"""
Importador de resultados de NetExec (nxc/nxcdb).

Lee las bases de datos por protocolo del workspace de NetExec y los archivos de
loot (sam, lsa, ntds, dpapi) y los normaliza para inyectarlos en el modelo de
escaneos de ArsenalOT.

Equivalencia con ``nxcdb`` interactivo: cargar ``smb.db`` directamente produce
las mismas columnas que ``proto smb; export hosts|creds detailed`` (incluidos
los mismos identificadores y pillaged_from). Ambos caminos son intercambiables;
se elige la lectura directa para evitar depender del binario nxc en tiempo de
ejecución (por ejemplo, en el contenedor Docker no está instalado).

No se filtra por fecha: NetExec no guarda timestamps por fila y los mtimes de
las DBs no se corresponden 1-a-1 con una auditoría concreta. El importador
carga TODO lo que haya en el workspace. Es responsabilidad del usuario limpiar
la DB de NetExec entre clientes (``nxcdb`` → ``proto X`` → ``clear_database``).
"""

from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Mapeo protocolo NetExec -> (puerto por defecto, protocolo de transporte, service_name)
PROTOCOL_PORT_MAP: Dict[str, Tuple[int, str, str]] = {
    'ftp':   (21,   'tcp', 'ftp'),
    'ssh':   (22,   'tcp', 'ssh'),
    'wmi':   (135,  'tcp', 'msrpc'),
    'ldap':  (389,  'tcp', 'ldap'),
    'smb':   (445,  'tcp', 'microsoft-ds'),
    'mssql': (1433, 'tcp', 'ms-sql-s'),
    'nfs':   (2049, 'tcp', 'nfs'),
    'rdp':   (3389, 'tcp', 'ms-wbt-server'),
    'vnc':   (5900, 'tcp', 'vnc'),
    'winrm': (5985, 'tcp', 'wsman'),
}

LOOT_KINDS = ('sam', 'lsa', 'ntds', 'dpapi')

# Regex para los nombres de archivo de loot:
#   HOSTNAME_IP_YYYY-MM-DD_HHMMSS[.ext]
_LOOT_FILE_RE = re.compile(
    r'^(?P<host>[^_]+)_(?P<ip>\d{1,3}(?:\.\d{1,3}){3})_'
    r'(?P<date>\d{4}-\d{2}-\d{2})_(?P<time>\d{6})'
)


@dataclass
class NetExecHost:
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[str] = None
    protocols: Dict[str, dict] = field(default_factory=dict)
    shares: List[dict] = field(default_factory=list)
    admin_users: List[str] = field(default_factory=list)
    loggedin_users: List[str] = field(default_factory=list)
    loot_files: List[dict] = field(default_factory=list)
    last_seen: Optional[datetime] = None


@dataclass
class NetExecCredential:
    domain: Optional[str]
    username: str
    password: Optional[str]
    credtype: Optional[str]
    source_protocol: str
    source_host_ip: Optional[str] = None
    source_host_hostname: Optional[str] = None


def _candidate_nxc_homes(explicit: Optional[Path] = None) -> List[Path]:
    """Orden de búsqueda para localizar un directorio ``.nxc``.

    Funciona bajo sudo/Docker donde ``Path.home()`` suele resolver a
    ``/root`` pese a que los datos viven en el home del usuario que invocó
    el proceso. Orden de prioridad:

      1. Ruta explícita pasada por parámetro (UI)
      2. ``ARSENAL_NXC_PATH`` (override propio de la app)
      3. ``NXC_PATH`` (única env var canónica de NetExec / nxcdb)
      4. ``Path.home() / .nxc``
      5. Home del usuario en ``SUDO_USER``
      6. Home de TODOS los usuarios reales del sistema (``pwd.getpwall``)
      7. Cualquier directorio bajo ``/home``
      8. ``/root/.nxc``
    """
    candidates: List[Path] = []

    if explicit:
        candidates.append(Path(explicit))

    for var in ('ARSENAL_NXC_PATH', 'NXC_PATH'):
        env = os.environ.get(var)
        if env:
            candidates.append(Path(env))

    try:
        candidates.append(Path.home() / '.nxc')
    except (RuntimeError, KeyError):
        pass

    try:
        import pwd
    except ImportError:
        pwd = None  # type: ignore

    sudo_user = os.environ.get('SUDO_USER')
    if pwd and sudo_user and sudo_user != 'root':
        try:
            candidates.append(Path(pwd.getpwnam(sudo_user).pw_dir) / '.nxc')
        except (KeyError, OSError):
            pass

    # Enumerar todos los usuarios reales del sistema (UID >= 1000 por defecto
    # en Linux para excluir cuentas de servicio, pero incluimos también root).
    if pwd:
        try:
            for entry in pwd.getpwall():
                if not entry.pw_dir:
                    continue
                if entry.pw_name == 'root' or entry.pw_uid >= 1000:
                    candidates.append(Path(entry.pw_dir) / '.nxc')
        except OSError:
            pass

    home_root = Path('/home')
    if home_root.is_dir():
        try:
            for user_dir in sorted(home_root.iterdir()):
                candidates.append(user_dir / '.nxc')
        except OSError:
            pass

    candidates.append(Path('/root/.nxc'))

    # Deduplicar preservando orden
    seen, ordered = set(), []
    for c in candidates:
        key = str(c)
        if key not in seen:
            seen.add(key)
            ordered.append(c)
    return ordered


def _pick_nxc_home(subdir: str, explicit: Optional[Path] = None) -> Path:
    """Devuelve el primer candidato con <home>/<subdir> presente; si ninguno
    existe, el primero de la lista (para que el mensaje de error sea útil)."""
    cands = _candidate_nxc_homes(explicit)
    for home in cands:
        if (home / subdir).is_dir():
            return home / subdir
    return cands[0] / subdir


def default_workspace_root(explicit: Optional[Path] = None) -> Path:
    """Raíz por defecto donde NetExec guarda los workspaces.

    Respeta ``ARSENAL_NXC_PATH`` y ``NXC_PATH`` si están definidos. Si no,
    busca automáticamente en el home del usuario actual, del usuario que
    invocó sudo y de cualquier usuario real del sistema.
    """
    return _pick_nxc_home('workspaces', explicit)


def default_logs_root(explicit: Optional[Path] = None) -> Path:
    """Raíz por defecto del directorio de loot/logs de NetExec."""
    return _pick_nxc_home('logs', explicit)


def searched_paths(explicit: Optional[Path] = None) -> List[str]:
    """Lista las rutas inspeccionadas (para mensajes de diagnóstico)."""
    return [str(p) for p in _candidate_nxc_homes(explicit)]


def list_workspaces(root: Optional[Path] = None) -> List[str]:
    """Devuelve los nombres de los workspaces disponibles."""
    root = root or default_workspace_root()
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def _parse_loot_filename(name: str) -> Optional[dict]:
    """Devuelve {hostname, ip, timestamp} o None si no encaja con el patrón."""
    m = _LOOT_FILE_RE.match(name)
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{m.group('date')}_{m.group('time')}",
                               "%Y-%m-%d_%H%M%S")
    except ValueError:
        return None
    return {'hostname': m.group('host'), 'ip': m.group('ip'), 'timestamp': ts}


def collect_loot(logs_root: Optional[Path] = None) -> List[dict]:
    """Recorre los directorios de loot y devuelve metadata de cada archivo.

    Estructura de salida:
        [{kind, path, hostname, ip, timestamp}, ...]
    """
    logs_root = logs_root or default_logs_root()
    out: List[dict] = []
    if not logs_root.exists():
        return out

    for kind in LOOT_KINDS:
        d = logs_root / kind
        if not d.is_dir():
            continue
        for entry in d.iterdir():
            if not entry.is_file():
                continue
            parsed = _parse_loot_filename(entry.name)
            if not parsed:
                continue
            out.append({
                'kind': kind,
                'path': str(entry),
                'hostname': parsed['hostname'],
                'ip': parsed['ip'],
                'timestamp': parsed['timestamp'],
                'size': entry.stat().st_size,
            })
    return out


def workspace_date_range(workspace_path: Path,
                         logs_root: Optional[Path] = None
                         ) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Estima el rango temporal disponible para un workspace.

    Combina el mtime de las DBs con los timestamps de los loot files.
    """
    timestamps: List[datetime] = []

    if workspace_path.exists():
        for db in workspace_path.glob('*.db'):
            try:
                timestamps.append(datetime.fromtimestamp(db.stat().st_mtime))
            except OSError:
                pass

    for item in collect_loot(logs_root):
        timestamps.append(item['timestamp'])

    if not timestamps:
        return None, None
    return min(timestamps), max(timestamps)


def _safe_query(db_path: Path, sql: str) -> List[sqlite3.Row]:
    """Ejecuta una consulta tolerando que la tabla/columna no exista."""
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            return list(conn.execute(sql))
        finally:
            conn.close()
    except sqlite3.Error:
        return []


def _load_smb(db_path: Path, hosts: Dict[str, NetExecHost]) -> Tuple[List[NetExecCredential], List[dict]]:
    """Carga datos de smb.db. Devuelve (credenciales, dpapi_secrets)."""
    creds: List[NetExecCredential] = []
    dpapi: List[dict] = []

    rows = _safe_query(db_path, "SELECT id, ip, hostname, domain, os, dc, smbv1, signing, "
                                "spooler, zerologon, petitpotam FROM hosts")
    host_id_by_ip: Dict[int, str] = {}
    hostname_to_ip: Dict[str, str] = {}

    for r in rows:
        ip = r['ip']
        if not ip:
            continue
        host = hosts.setdefault(ip, NetExecHost(ip=ip))
        host.hostname = host.hostname or r['hostname']
        host.domain = host.domain or r['domain']
        host.os = host.os or r['os']
        host.protocols['smb'] = {
            'port': 445,
            'dc': bool(r['dc']) if r['dc'] is not None else None,
            'smbv1': bool(r['smbv1']) if r['smbv1'] is not None else None,
            'signing': bool(r['signing']) if r['signing'] is not None else None,
            'spooler': bool(r['spooler']) if r['spooler'] is not None else None,
            'zerologon': bool(r['zerologon']) if r['zerologon'] is not None else None,
            'petitpotam': bool(r['petitpotam']) if r['petitpotam'] is not None else None,
        }
        host_id_by_ip[r['id']] = ip
        if r['hostname']:
            hostname_to_ip[r['hostname']] = ip

    user_rows = _safe_query(db_path, "SELECT id, domain, username, password, credtype, "
                                     "pillaged_from_hostid FROM users")
    user_id_to_name: Dict[int, str] = {}
    for r in user_rows:
        if not r['username']:
            continue
        src_ip = host_id_by_ip.get(r['pillaged_from_hostid']) if r['pillaged_from_hostid'] else None
        creds.append(NetExecCredential(
            domain=r['domain'],
            username=r['username'],
            password=r['password'],
            credtype=r['credtype'],
            source_protocol='smb',
            source_host_ip=src_ip,
        ))
        user_id_to_name[r['id']] = r['username']

    # shares: hostid es texto = hostname (a pesar del schema que dice INTEGER)
    share_rows = _safe_query(db_path, "SELECT hostid, userid, name, remark, read, write FROM shares")
    for r in share_rows:
        target_ip = hostname_to_ip.get(str(r['hostid'])) if r['hostid'] else None
        if not target_ip:
            continue
        host = hosts.setdefault(target_ip, NetExecHost(ip=target_ip))
        host.shares.append({
            'name': r['name'],
            'remark': r['remark'],
            'read': bool(r['read']) if r['read'] is not None else None,
            'write': bool(r['write']) if r['write'] is not None else None,
            'user': user_id_to_name.get(r['userid']),
        })

    admin_rows = _safe_query(db_path, "SELECT userid, hostid FROM admin_relations")
    for r in admin_rows:
        ip = host_id_by_ip.get(r['hostid'])
        uname = user_id_to_name.get(r['userid'])
        if ip and uname:
            host = hosts.setdefault(ip, NetExecHost(ip=ip))
            if uname not in host.admin_users:
                host.admin_users.append(uname)

    loggedin_rows = _safe_query(db_path, "SELECT userid, hostid FROM loggedin_relations")
    for r in loggedin_rows:
        ip = host_id_by_ip.get(r['hostid'])
        uname = user_id_to_name.get(r['userid'])
        if ip and uname:
            host = hosts.setdefault(ip, NetExecHost(ip=ip))
            if uname not in host.loggedin_users:
                host.loggedin_users.append(uname)

    dpapi_rows = _safe_query(db_path, "SELECT host, dpapi_type, windows_user, username, "
                                      "password, url FROM dpapi_secrets")
    for r in dpapi_rows:
        dpapi.append({
            'host': r['host'],
            'dpapi_type': r['dpapi_type'],
            'windows_user': r['windows_user'],
            'username': r['username'],
            'password': r['password'],
            'url': r['url'],
        })
        if r['username']:
            creds.append(NetExecCredential(
                domain=None,
                username=r['username'],
                password=r['password'],
                credtype='dpapi',
                source_protocol='smb-dpapi',
                source_host_ip=r['host'] if r['host'] and re.match(r'^\d+\.\d+\.\d+\.\d+$', str(r['host'])) else None,
            ))

    return creds, dpapi


def _load_simple_protocol(db_path: Path,
                          protocol: str,
                          hosts: Dict[str, NetExecHost]) -> List[NetExecCredential]:
    """Carga DBs con esquema 'simple': hosts(host/ip, port, banner[, os]) + credentials."""
    creds: List[NetExecCredential] = []
    if not db_path.exists():
        return creds

    # Detectar el nombre real de la columna IP
    schema = _safe_query(db_path, "PRAGMA table_info(hosts)")
    cols = {row['name'] for row in schema}
    ip_col = 'ip' if 'ip' in cols else ('host' if 'host' in cols else None)
    if not ip_col:
        return creds

    select_cols = [ip_col]
    for opt in ('hostname', 'port', 'banner', 'os', 'server_banner'):
        if opt in cols:
            select_cols.append(opt)

    sql = f"SELECT {', '.join(select_cols)} FROM hosts"
    for r in _safe_query(db_path, sql):
        ip = r[ip_col]
        if not ip:
            continue
        host = hosts.setdefault(ip, NetExecHost(ip=ip))
        if 'hostname' in cols and r['hostname']:
            host.hostname = host.hostname or r['hostname']
        if 'os' in cols and r['os']:
            host.os = host.os or r['os']
        port = r['port'] if 'port' in cols else PROTOCOL_PORT_MAP[protocol][0]
        banner = None
        if 'banner' in cols and r['banner']:
            banner = r['banner']
        elif 'server_banner' in cols and r['server_banner']:
            banner = r['server_banner']
        host.protocols[protocol] = {
            'port': port or PROTOCOL_PORT_MAP[protocol][0],
            'banner': banner,
        }

    # Credentials/users (cualquiera de las dos formas)
    cred_table = None
    table_check = _safe_query(db_path, "SELECT name FROM sqlite_master WHERE type='table'")
    table_names = {row['name'] for row in table_check}
    if 'credentials' in table_names:
        cred_table = 'credentials'
    elif 'users' in table_names:
        cred_table = 'users'

    if cred_table:
        cred_schema = _safe_query(db_path, f"PRAGMA table_info({cred_table})")
        cred_cols = {row['name'] for row in cred_schema}
        select = ['id', 'username', 'password']
        for opt in ('domain', 'credtype'):
            if opt in cred_cols:
                select.append(opt)
        for r in _safe_query(db_path, f"SELECT {', '.join(select)} FROM {cred_table}"):
            if not r['username']:
                continue
            creds.append(NetExecCredential(
                domain=r['domain'] if 'domain' in cred_cols else None,
                username=r['username'],
                password=r['password'],
                credtype=r['credtype'] if 'credtype' in cred_cols else None,
                source_protocol=protocol,
            ))

    return creds


def _load_ldap(db_path: Path, hosts: Dict[str, NetExecHost]) -> List[NetExecCredential]:
    creds: List[NetExecCredential] = []
    for r in _safe_query(db_path, "SELECT ip, hostname, domain, os, signing_required, "
                                  "channel_binding FROM hosts"):
        ip = r['ip']
        if not ip:
            continue
        host = hosts.setdefault(ip, NetExecHost(ip=ip))
        host.hostname = host.hostname or r['hostname']
        host.domain = host.domain or r['domain']
        host.os = host.os or r['os']
        host.protocols['ldap'] = {
            'port': 389,
            'signing_required': bool(r['signing_required']) if r['signing_required'] is not None else None,
            'channel_binding': r['channel_binding'],
        }
    for r in _safe_query(db_path, "SELECT domain, username, password, credtype FROM users"):
        if not r['username']:
            continue
        creds.append(NetExecCredential(
            domain=r['domain'], username=r['username'], password=r['password'],
            credtype=r['credtype'], source_protocol='ldap'))
    return creds


def _load_mssql(db_path: Path, hosts: Dict[str, NetExecHost]) -> List[NetExecCredential]:
    creds: List[NetExecCredential] = []
    for r in _safe_query(db_path, "SELECT ip, hostname, domain, os, instances FROM hosts"):
        ip = r['ip']
        if not ip:
            continue
        host = hosts.setdefault(ip, NetExecHost(ip=ip))
        host.hostname = host.hostname or r['hostname']
        host.domain = host.domain or r['domain']
        host.os = host.os or r['os']
        host.protocols['mssql'] = {'port': 1433, 'instances': r['instances']}
    for r in _safe_query(db_path, "SELECT domain, username, password, credtype FROM users"):
        if not r['username']:
            continue
        creds.append(NetExecCredential(
            domain=r['domain'], username=r['username'], password=r['password'],
            credtype=r['credtype'], source_protocol='mssql'))
    return creds


def _load_rdp(db_path: Path, hosts: Dict[str, NetExecHost]) -> None:
    for r in _safe_query(db_path, "SELECT ip, port, hostname, domain, os, nla FROM hosts"):
        ip = r['ip']
        if not ip:
            continue
        host = hosts.setdefault(ip, NetExecHost(ip=ip))
        host.hostname = host.hostname or r['hostname']
        host.domain = host.domain or r['domain']
        host.os = host.os or r['os']
        host.protocols['rdp'] = {
            'port': r['port'] or 3389,
            'nla': bool(r['nla']) if r['nla'] is not None else None,
        }


def _load_winrm(db_path: Path, hosts: Dict[str, NetExecHost]) -> List[NetExecCredential]:
    creds: List[NetExecCredential] = []
    for r in _safe_query(db_path, "SELECT ip, port, hostname, domain, os FROM hosts"):
        ip = r['ip']
        if not ip:
            continue
        host = hosts.setdefault(ip, NetExecHost(ip=ip))
        host.hostname = host.hostname or r['hostname']
        host.domain = host.domain or r['domain']
        host.os = host.os or r['os']
        host.protocols['winrm'] = {'port': r['port'] or 5985}
    for r in _safe_query(db_path, "SELECT domain, username, password, credtype FROM users"):
        if not r['username']:
            continue
        creds.append(NetExecCredential(
            domain=r['domain'], username=r['username'], password=r['password'],
            credtype=r['credtype'], source_protocol='winrm'))
    return creds


def import_workspace(workspace_path: Path,
                     logs_root: Optional[Path] = None) -> dict:
    """Importa un workspace de NetExec completo (sin filtros)."""
    workspace_path = Path(workspace_path)
    if not workspace_path.is_dir():
        raise FileNotFoundError(f"Workspace no encontrado: {workspace_path}")

    hosts: Dict[str, NetExecHost] = {}
    creds: List[NetExecCredential] = []
    dpapi_secrets: List[dict] = []

    smb_db = workspace_path / 'smb.db'
    if smb_db.exists():
        sc, ds = _load_smb(smb_db, hosts)
        creds.extend(sc)
        dpapi_secrets.extend(ds)

    ldap_db = workspace_path / 'ldap.db'
    if ldap_db.exists():
        creds.extend(_load_ldap(ldap_db, hosts))

    mssql_db = workspace_path / 'mssql.db'
    if mssql_db.exists():
        creds.extend(_load_mssql(mssql_db, hosts))

    rdp_db = workspace_path / 'rdp.db'
    if rdp_db.exists():
        _load_rdp(rdp_db, hosts)

    winrm_db = workspace_path / 'winrm.db'
    if winrm_db.exists():
        creds.extend(_load_winrm(winrm_db, hosts))

    for proto in ('ftp', 'ssh', 'nfs', 'vnc', 'wmi'):
        db = workspace_path / f'{proto}.db'
        if db.exists():
            creds.extend(_load_simple_protocol(db, proto, hosts))

    # Loot vive en ~/.nxc/logs/ y es GLOBAL a todos los workspaces. Para no
    # traer hosts fantasma al importar un workspace limpio, sólo asociamos un
    # loot file si su IP ya aparece en las DBs del workspace.
    for item in collect_loot(logs_root):
        ip = item['ip']
        host = hosts.get(ip)
        if not host:
            continue
        host.hostname = host.hostname or item['hostname']
        host.loot_files.append(item)
        if not host.last_seen or item['timestamp'] > host.last_seen:
            host.last_seen = item['timestamp']

    summary = {
        'workspace': workspace_path.name,
        'hosts_total': len(hosts),
        'credentials_total': len(creds),
        'dpapi_secrets_total': len(dpapi_secrets),
        'loot_files_total': sum(len(h.loot_files) for h in hosts.values()),
        'protocols_seen': sorted({p for h in hosts.values() for p in h.protocols}),
    }

    return {
        'workspace': workspace_path.name,
        'workspace_path': str(workspace_path),
        'hosts': hosts,
        'credentials': creds,
        'dpapi_secrets': dpapi_secrets,
        'summary': summary,
    }


def global_date_range(root: Optional[Path] = None,
                      logs_root: Optional[Path] = None,
                      explicit: Optional[Path] = None
                      ) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Rango temporal combinado de TODOS los workspaces + loot files."""
    root = root or default_workspace_root(explicit)
    logs_root = logs_root or default_logs_root(explicit)
    timestamps: List[datetime] = []
    if root.exists():
        for ws in root.iterdir():
            if not ws.is_dir():
                continue
            for db in ws.glob('*.db'):
                try:
                    timestamps.append(datetime.fromtimestamp(db.stat().st_mtime))
                except OSError:
                    pass
    for item in collect_loot(logs_root):
        timestamps.append(item['timestamp'])
    if not timestamps:
        return None, None
    return min(timestamps), max(timestamps)


def import_all_workspaces(root: Optional[Path] = None,
                          logs_root: Optional[Path] = None,
                          explicit: Optional[Path] = None) -> dict:
    """Importa TODOS los workspaces de NetExec mergeando resultados por IP."""
    root = root or default_workspace_root(explicit)
    logs_root = logs_root or default_logs_root(explicit)
    if not root.exists():
        raise FileNotFoundError(f"Raíz de workspaces no encontrada: {root}")

    workspaces = [p for p in sorted(root.iterdir()) if p.is_dir()]
    if not workspaces:
        raise FileNotFoundError(f"Sin workspaces bajo {root}")

    merged_hosts: Dict[str, NetExecHost] = {}
    all_creds: List[NetExecCredential] = []
    all_dpapi: List[dict] = []
    ws_names: List[str] = []

    for ws_path in workspaces:
        ws_names.append(ws_path.name)
        sub = _import_workspace_raw(ws_path)
        for ip, h in sub['hosts'].items():
            cur = merged_hosts.setdefault(ip, NetExecHost(ip=ip))
            cur.hostname = cur.hostname or h.hostname
            cur.domain = cur.domain or h.domain
            cur.os = cur.os or h.os
            for proto, meta in h.protocols.items():
                cur.protocols.setdefault(proto, meta)
            for s in h.shares:
                if s not in cur.shares:
                    cur.shares.append(s)
            for u in h.admin_users:
                if u not in cur.admin_users:
                    cur.admin_users.append(u)
            for u in h.loggedin_users:
                if u not in cur.loggedin_users:
                    cur.loggedin_users.append(u)
        all_creds.extend(sub['credentials'])
        all_dpapi.extend(sub['dpapi_secrets'])

    # Loot sólo se asocia a hosts que realmente aparecen en alguna DB; así
    # evitamos materializar hosts fantasma de auditorías anteriores ya
    # purgadas del workspace pero con ficheros residuales en ~/.nxc/logs/.
    for item in collect_loot(logs_root):
        ip = item['ip']
        host = merged_hosts.get(ip)
        if not host:
            continue
        host.hostname = host.hostname or item['hostname']
        host.loot_files.append(item)
        if not host.last_seen or item['timestamp'] > host.last_seen:
            host.last_seen = item['timestamp']

    summary = {
        'workspaces': ws_names,
        'hosts_total': len(merged_hosts),
        'credentials_total': len(all_creds),
        'dpapi_secrets_total': len(all_dpapi),
        'loot_files_total': sum(len(h.loot_files) for h in merged_hosts.values()),
        'protocols_seen': sorted({p for h in merged_hosts.values() for p in h.protocols}),
    }
    return {
        'workspace': '+'.join(ws_names) if ws_names else '',
        'workspace_path': str(root),
        'hosts': merged_hosts,
        'credentials': all_creds,
        'dpapi_secrets': all_dpapi,
        'summary': summary,
    }


def _import_workspace_raw(workspace_path: Path) -> dict:
    """Carga todas las DBs de un workspace sin asociar loot."""
    hosts: Dict[str, NetExecHost] = {}
    creds: List[NetExecCredential] = []
    dpapi_secrets: List[dict] = []

    smb_db = workspace_path / 'smb.db'
    if smb_db.exists():
        sc, ds = _load_smb(smb_db, hosts)
        creds.extend(sc)
        dpapi_secrets.extend(ds)
    ldap_db = workspace_path / 'ldap.db'
    if ldap_db.exists():
        creds.extend(_load_ldap(ldap_db, hosts))
    mssql_db = workspace_path / 'mssql.db'
    if mssql_db.exists():
        creds.extend(_load_mssql(mssql_db, hosts))
    rdp_db = workspace_path / 'rdp.db'
    if rdp_db.exists():
        _load_rdp(rdp_db, hosts)
    winrm_db = workspace_path / 'winrm.db'
    if winrm_db.exists():
        creds.extend(_load_winrm(winrm_db, hosts))
    for proto in ('ftp', 'ssh', 'nfs', 'vnc', 'wmi'):
        db = workspace_path / f'{proto}.db'
        if db.exists():
            creds.extend(_load_simple_protocol(db, proto, hosts))

    return {'hosts': hosts, 'credentials': creds, 'dpapi_secrets': dpapi_secrets}


def serialize_for_api(import_result: dict) -> dict:
    """Convierte el resultado de import_workspace a dicts JSON-serializables."""
    hosts_out = []
    for h in import_result['hosts'].values():
        hosts_out.append({
            'ip': h.ip,
            'hostname': h.hostname,
            'domain': h.domain,
            'os': h.os,
            'protocols': h.protocols,
            'shares': h.shares,
            'admin_users': h.admin_users,
            'loggedin_users': h.loggedin_users,
            'loot_files': [{
                'kind': l['kind'],
                'path': l['path'],
                'timestamp': l['timestamp'].isoformat(),
                'size': l.get('size'),
            } for l in h.loot_files],
            'last_seen': h.last_seen.isoformat() if h.last_seen else None,
        })

    creds_out = [{
        'domain': c.domain,
        'username': c.username,
        'password': c.password,
        'credtype': c.credtype,
        'source_protocol': c.source_protocol,
        'source_host_ip': c.source_host_ip,
    } for c in import_result['credentials']]

    return {
        'workspace': import_result['workspace'],
        'workspace_path': import_result['workspace_path'],
        'summary': import_result['summary'],
        'hosts': hosts_out,
        'credentials': creds_out,
        'dpapi_secrets': import_result['dpapi_secrets'],
    }
