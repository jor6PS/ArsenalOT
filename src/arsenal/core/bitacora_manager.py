"""
Gestor de la bitácora Obsidian integrada en ArsenalOT.

Cada organización tiene su carpeta dentro del vault compartido:
  results/bitacora/
    .obsidian/            ← config Obsidian (copiada del template una vez)
    imagenes/             ← imágenes compartidas (del template)
    Organizaciones/
      {ORG_NAME}/
        PENTEST IT OT/    ← copia del template
        EV. DISPOSITIVOS/ ← copia del template
"""

import os
import shutil
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# Directorio del template (en el propio repositorio)
TEMPLATE_DIR = Path(__file__).parent / "bitacora obsidian"

# Directorio raíz del vault (relativo al results_root que recibe ScanStorage)
VAULT_SUBDIR = "bitacora"

# Subcarpeta dentro del vault donde van las orgs
ORGS_SUBDIR = "Organizaciones"

# Subdirectorios del template que se copian por org
ORG_TEMPLATE_SUBDIRS = ["PENTEST IT OT", "EV. DISPOSITIVOS"]

# Archivos/dirs del template que van a la raíz del vault (solo primera vez)
VAULT_ROOT_ITEMS = [".obsidian", "imagenes"]

# Marcadores del bloque de visibilidad gestionado por ArsenalOT
VISIBILIDAD_START = '<!-- ARSENAL:VISIBILIDAD -->'
VISIBILIDAD_END   = '<!-- /ARSENAL:VISIBILIDAD -->'


def _safe_path(base: Path, user_path: str) -> Path:
    """Resuelve un path relativo y verifica que no salga del base (path traversal)."""
    resolved = (base / user_path.lstrip("/")).resolve()
    if not str(resolved).startswith(str(base.resolve())):
        raise PermissionError(f"Path traversal bloqueado: {user_path!r}")
    return resolved


def _open_permissions(path: Path):
    """
    Hace que un archivo o directorio sea legible/escribible por cualquier usuario.
    Archivos → 0o666, Directorios → 0o777.
    Si path es un directorio, aplica recursivamente a todo su contenido.
    Silencia errores (p.ej. si el proceso no es el propietario).
    """
    try:
        if path.is_dir():
            os.chmod(path, 0o777)
            for child in path.rglob("*"):
                try:
                    os.chmod(child, 0o777 if child.is_dir() else 0o666)
                except OSError:
                    pass
        else:
            os.chmod(path, 0o666)
    except OSError:
        pass


class BitacoraManager:
    """Gestiona la bitácora Obsidian integrada."""

    def __init__(self, results_root: Path):
        self.results_root = Path(results_root)
        self.vault_root = self.results_root / VAULT_SUBDIR
        self.orgs_root = self.vault_root / ORGS_SUBDIR
        self._init_vault()

    # ─────────────────────────────────────────────────────────
    # Inicialización del vault raíz
    # ─────────────────────────────────────────────────────────

    def _init_vault(self):
        """Crea el vault raíz la primera vez (config Obsidian + imágenes compartidas)."""
        self.vault_root.mkdir(parents=True, exist_ok=True)
        _open_permissions(self.vault_root)
        self.orgs_root.mkdir(parents=True, exist_ok=True)
        _open_permissions(self.orgs_root)

        if not TEMPLATE_DIR.exists():
            return  # template no disponible (entorno de test sin repo)

        for item_name in VAULT_ROOT_ITEMS:
            src = TEMPLATE_DIR / item_name
            dst = self.vault_root / item_name
            if src.exists() and not dst.exists():
                if src.is_dir():
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
                _open_permissions(dst)

    # ─────────────────────────────────────────────────────────
    # Creación de bitácora para una organización
    # ─────────────────────────────────────────────────────────

    def create_org_bitacora(self, org_name: str) -> Path:
        """
        Crea la estructura de bitácora para una organización nueva.
        Si ya existe, no sobreescribe nada.
        Devuelve la ruta del directorio de la org.
        """
        org_dir = self.orgs_root / org_name
        org_dir.mkdir(parents=True, exist_ok=True)
        _open_permissions(org_dir)

        if not TEMPLATE_DIR.exists():
            # Crear estructura mínima si no hay template
            for _d in [
                org_dir / "PENTEST IT OT" / "Bitacoras",
                org_dir / "PENTEST IT OT" / "Plantillas",
                org_dir / "EV. DISPOSITIVOS" / "62443" / "Bitacoras",
            ]:
                _d.mkdir(parents=True, exist_ok=True)
                _open_permissions(_d)
            return org_dir

        for subdir_name in ORG_TEMPLATE_SUBDIRS:
            src = TEMPLATE_DIR / subdir_name
            dst = org_dir / subdir_name
            if src.exists() and not dst.exists():
                shutil.copytree(src, dst)
                _open_permissions(dst)

        # Crear README de la org si no existe
        readme = org_dir / "README.md"
        if not readme.exists():
            readme.write_text(
                f"# Bitácora — {org_name}\n\n"
                f"Notas y registros de la evaluación de la organización **{org_name}**.\n\n"
                f"## Estructura\n\n"
                f"- `PENTEST IT OT/` — Pentesting IT/OT: guías, plantillas y registros\n"
                f"- `EV. DISPOSITIVOS/` — Evaluación IEC 62443 de dispositivos OT\n\n"
                f"## Cómo usar\n\n"
                f"Abre la carpeta `bitacora/` desde Obsidian como vault. "
                f"Los cambios se sincronizan en tiempo real con ArsenalOT.\n",
                encoding="utf-8"
            )
            _open_permissions(readme)

        return org_dir

    def get_org_dir(self, org_name: str) -> Path:
        """Devuelve la ruta del directorio de la org (creándola si no existe)."""
        org_dir = self.orgs_root / org_name
        if not org_dir.exists():
            self.create_org_bitacora(org_name)
        return org_dir

    # ─────────────────────────────────────────────────────────
    # Árbol de archivos
    # ─────────────────────────────────────────────────────────

    def get_file_tree(self, org_name: str) -> List[Dict]:
        """
        Devuelve el árbol de archivos de la bitácora de una org.
        Cada nodo: {name, path (relativo a org_dir), type: 'file'|'dir', children?}
        """
        org_dir = self.get_org_dir(org_name)
        return self._build_tree(org_dir, org_dir)

    def _build_tree(self, base: Path, root: Path) -> List[Dict]:
        nodes = []
        try:
            entries = sorted(base.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except PermissionError:
            return []

        for entry in entries:
            # Skip hidden files except .obsidian links, skip __pycache__
            if entry.name.startswith(".") or entry.name == "__pycache__":
                continue
            rel = entry.relative_to(root).as_posix()
            if entry.is_dir():
                children = self._build_tree(entry, root)
                nodes.append({"name": entry.name, "path": rel, "type": "dir", "children": children})
            else:
                stat = entry.stat()
                nodes.append({
                    "name": entry.name,
                    "path": rel,
                    "type": "file",
                    "mtime": stat.st_mtime,
                    "size": stat.st_size,
                })
        return nodes

    # ─────────────────────────────────────────────────────────
    # CRUD de archivos
    # ─────────────────────────────────────────────────────────

    def read_file(self, org_name: str, rel_path: str) -> Tuple[str, float]:
        """
        Lee un archivo y devuelve (contenido, mtime).
        mtime se usa como ETag para detección de conflictos.
        """
        org_dir = self.get_org_dir(org_name)
        fpath = _safe_path(org_dir, rel_path)
        if not fpath.exists() or not fpath.is_file():
            raise FileNotFoundError(f"Archivo no encontrado: {rel_path}")
        content = fpath.read_text(encoding="utf-8", errors="replace")
        mtime = fpath.stat().st_mtime
        return content, mtime

    def write_file(
        self,
        org_name: str,
        rel_path: str,
        content: str,
        client_mtime: Optional[float] = None,
    ) -> Tuple[bool, Optional[str], float]:
        """
        Guarda un archivo.

        Si client_mtime se proporciona, compara con el mtime actual:
          - Si el archivo fue modificado desde que el cliente lo cargó → conflicto
          - Devuelve (False, contenido_conflictivo, mtime_actual)

        Si no hay conflicto (o es archivo nuevo):
          - Devuelve (True, None, nuevo_mtime)
        """
        org_dir = self.get_org_dir(org_name)
        fpath = _safe_path(org_dir, rel_path)

        # Detectar conflicto
        if client_mtime is not None and fpath.exists():
            current_mtime = fpath.stat().st_mtime
            # Tolerancia de 1 segundo para sistemas de archivos con baja resolución
            if abs(current_mtime - client_mtime) > 1.0:
                # El archivo cambió en disco (edición desde Obsidian u otro proceso)
                current_content = fpath.read_text(encoding="utf-8", errors="replace")
                return False, current_content, current_mtime

        # Crear directorios intermedios si hace falta
        fpath.parent.mkdir(parents=True, exist_ok=True)
        _open_permissions(fpath.parent)
        fpath.write_text(content, encoding="utf-8")
        _open_permissions(fpath)
        new_mtime = fpath.stat().st_mtime
        return True, None, new_mtime

    def create_file(self, org_name: str, rel_path: str, initial_content: str = "") -> float:
        """Crea un archivo nuevo (error si ya existe)."""
        org_dir = self.get_org_dir(org_name)
        fpath = _safe_path(org_dir, rel_path)
        if fpath.exists():
            raise FileExistsError(f"El archivo ya existe: {rel_path}")
        fpath.parent.mkdir(parents=True, exist_ok=True)
        _open_permissions(fpath.parent)
        fpath.write_text(initial_content, encoding="utf-8")
        _open_permissions(fpath)
        return fpath.stat().st_mtime

    def delete_file(self, org_name: str, rel_path: str):
        """Elimina un archivo o directorio vacío."""
        org_dir = self.get_org_dir(org_name)
        fpath = _safe_path(org_dir, rel_path)
        if not fpath.exists():
            raise FileNotFoundError(f"No encontrado: {rel_path}")
        if fpath.is_dir():
            fpath.rmdir()  # solo si está vacío
        else:
            fpath.unlink()

    def create_folder(self, org_name: str, rel_path: str):
        """Crea una carpeta nueva."""
        org_dir = self.get_org_dir(org_name)
        fpath = _safe_path(org_dir, rel_path)
        fpath.mkdir(parents=True, exist_ok=True)
        _open_permissions(fpath)

    def rename(self, org_name: str, old_path: str, new_path: str):
        """Renombra/mueve un archivo o carpeta."""
        org_dir = self.get_org_dir(org_name)
        src = _safe_path(org_dir, old_path)
        dst = _safe_path(org_dir, new_path)
        if not src.exists():
            raise FileNotFoundError(f"No encontrado: {old_path}")
        if dst.exists():
            raise FileExistsError(f"Ya existe: {new_path}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        src.rename(dst)

    # ─────────────────────────────────────────────────────────
    # Info del vault
    # ─────────────────────────────────────────────────────────

    def get_vault_path(self) -> str:
        """Devuelve la ruta absoluta del vault para mostrarla al usuario."""
        return str(self.vault_root.resolve())

    # ─────────────────────────────────────────────────────────
    # Visibilidad de redes por escaneo (bloque auto-gestionado)
    # ─────────────────────────────────────────────────────────

    def _find_location_note_path(self, org_name: str, location: str) -> Optional[Path]:
        """Localiza el .md de un vector de acceso (location) en Bitacoras/."""
        bitacoras = self.get_org_dir(org_name) / "PENTEST IT OT" / "Bitacoras"
        if not bitacoras.exists():
            return None
        hits = list(bitacoras.glob(f"*VE - {location}.md"))
        return hits[0] if hits else None

    def _build_visibility_block(self, scan_id: int, db_path) -> str:  # kept for compat
        """Construye el bloque Markdown de visibilidad para un escaneo."""
        import sqlite3 as _sq
        import ipaddress as _ipa
        from datetime import datetime as _dt

        conn = _sq.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sq.Row
        try:
            scan = conn.execute(
                """SELECT id, organization_name, location, scan_mode, target_range,
                          interface, myip, started_at, completed_at,
                          hosts_discovered, ports_found
                   FROM scans WHERE id = ?""",
                (scan_id,)
            ).fetchone()
            if not scan:
                return ''

            org = scan['organization_name']

            # Redes registradas para la organización
            net_rows = conn.execute(
                """SELECT system_name, network_name, network_range
                   FROM networks
                   WHERE UPPER(organization_name) = UPPER(?)
                   ORDER BY system_name, network_name""",
                (org,)
            ).fetchall()

            known_nets = []
            for n in net_rows:
                try:
                    known_nets.append({
                        'obj':    _ipa.ip_network(n['network_range'], strict=False),
                        'name':   n['network_name'] or '—',
                        'system': n['system_name'] or '—',
                        'range':  n['network_range'],
                    })
                except ValueError:
                    pass

            is_passive = (scan['scan_mode'] or 'active') == 'passive'

            if is_passive:
                ip_rows = conn.execute(
                    """SELECT DISTINCT src_ip AS ip FROM passive_conversations WHERE scan_id = ?
                       UNION
                       SELECT DISTINCT dst_ip AS ip FROM passive_conversations WHERE scan_id = ?""",
                    (scan_id, scan_id)
                ).fetchall()
                hosts = [{'ip_address': r['ip'], 'hostname': None,
                          'mac_address': None, 'vendor': None}
                         for r in ip_rows]
                port_map: Dict = {}
                for pr in conn.execute(
                    """SELECT DISTINCT dst_ip, dst_port, protocol
                       FROM passive_conversations
                       WHERE scan_id = ? AND dst_port IS NOT NULL
                       ORDER BY dst_ip, dst_port""",
                    (scan_id,)
                ).fetchall():
                    port_map.setdefault(pr['dst_ip'], []).append(
                        f"{pr['dst_port']}/{pr['protocol'] or 'tcp'}"
                    )
            else:
                hosts = [dict(r) for r in conn.execute(
                    """SELECT DISTINCT h.ip_address, h.hostname,
                              h.mac_address, h.vendor
                       FROM scan_results sr
                       JOIN hosts h ON h.id = sr.host_id
                       WHERE sr.scan_id = ?
                       ORDER BY h.ip_address""",
                    (scan_id,)
                ).fetchall()]
                port_map = {}
                for pr in conn.execute(
                    """SELECT h.ip_address, sr.port, sr.protocol, sr.service_name
                       FROM scan_results sr
                       JOIN hosts h ON h.id = sr.host_id
                       WHERE sr.scan_id = ?
                         AND sr.port IS NOT NULL AND sr.state = 'open'
                       ORDER BY h.ip_address, sr.port""",
                    (scan_id,)
                ).fetchall():
                    svc = pr['service_name'] or str(pr['port'])
                    port_map.setdefault(pr['ip_address'], []).append(
                        f"{pr['port']}/{svc}"
                    )
        finally:
            conn.close()

        # Clasificar hosts: redes conocidas vs desconocidas
        net_count: Dict = {}   # range → {name, system, hosts[], known}
        unknown:   Dict = {}   # /24   → [ips]

        for h in hosts:
            ip_str = h['ip_address']
            try:
                host_ip = _ipa.ip_address(ip_str)
            except ValueError:
                continue
            matched = False
            for n in known_nets:
                if host_ip in n['obj']:
                    net_count.setdefault(n['range'], {
                        'name': n['name'], 'system': n['system'],
                        'hosts': [], 'known': True,
                    })['hosts'].append(ip_str)
                    matched = True
                    break
            if not matched:
                parts = ip_str.rsplit('.', 1)
                subnet = f"{parts[0]}.0/24" if len(parts) == 2 else '0.0.0.0/0'
                unknown.setdefault(subnet, []).append(ip_str)

        # Calcular duración del escaneo
        duration_str = ''
        try:
            if scan['started_at'] and scan['completed_at']:
                s = _dt.fromisoformat(str(scan['started_at'])[:19])
                e = _dt.fromisoformat(str(scan['completed_at'])[:19])
                mins = max(0, int((e - s).total_seconds() / 60))
                duration_str = f" · **Duración:** {mins} min"
        except Exception:
            pass

        mode_lbl   = 'Pasivo' if is_passive else 'Activo'
        origin_lbl = (f"ESCANEO PASIVO {scan_id}" if is_passive
                      else f"Escaneo {scan_id}")
        total_hosts = len(hosts) or (scan['hosts_discovered'] or 0)
        total_ports = sum(len(v) for v in port_map.values()) or (scan['ports_found'] or 0)

        lines = [
            VISIBILIDAD_START,
            '#### 🔍 Visibilidad de Redes — ArsenalOT',
            '',
            (f"**Origen:** `{origin_lbl}` · **Modo:** {mode_lbl}"
             f" · **Objetivo:** `{scan['target_range'] or '—'}`  "),
            (f"**Localización:** {scan['location'] or '—'}"
             f" · **Inicio:** {str(scan['started_at'] or '')[:10]}"
             f"{duration_str}"
             f" · **Hosts activos:** {total_hosts}"
             f" · **Puertos/servicios:** {total_ports}"),
            '',
        ]

        # Tabla de redes
        all_nets = (
            [{'range': r, **v} for r, v in net_count.items()] +
            [{'range': r, 'name': '—', 'system': '—', 'hosts': ips, 'known': False}
             for r, ips in unknown.items()]
        )
        if all_nets:
            all_nets.sort(key=lambda x: (not x['known'], x['range']))
            lines += [
                '##### Redes con Visibilidad',
                '',
                '| Red | Nombre | Sistema | Tipo | Hosts |',
                '|:---|:---|:---|:---|---:|',
            ]
            for n in all_nets:
                tipo = '✅ Conocida' if n['known'] else '⚠️ Desconocida'
                lines.append(
                    f"| `{n['range']}` | {n['name']} | {n['system']}"
                    f" | {tipo} | {len(n['hosts'])} |"
                )
            lines.append('')

        # Tabla de hosts
        if hosts:
            lines += [
                '##### Hosts Descubiertos',
                '',
                '| IP | Hostname | MAC / Vendor | Servicios detectados |',
                '|:---|:---|:---|:---|',
            ]
            for h in hosts:
                ip     = h['ip_address']
                hn     = h.get('hostname') or '—'
                mac    = h.get('mac_address') or ''
                vendor = h.get('vendor') or ''
                if mac and vendor:
                    mac_str = f"{mac} / {vendor}"
                elif mac:
                    mac_str = mac
                elif vendor:
                    mac_str = vendor
                else:
                    mac_str = '—'
                ports    = port_map.get(ip, [])
                svc_str  = ', '.join(ports[:8]) or '—'
                if len(ports) > 8:
                    svc_str += ', …'
                lines.append(
                    f"| `{ip}` | `{hn}` | {mac_str} | {svc_str} |"
                )
            lines.append('')

        lines.append(VISIBILIDAD_END)
        return '\n'.join(lines)

    def _inject_or_replace_visibility(self, content: str, block: str) -> str:
        """Reemplaza el bloque existente o lo inyecta antes de la sección 1.2."""
        if VISIBILIDAD_START in content and VISIBILIDAD_END in content:
            s = content.index(VISIBILIDAD_START)
            e = content.index(VISIBILIDAD_END) + len(VISIBILIDAD_END)
            return content[:s] + block + content[e:]
        # Inyectar antes de la sección 1.2 (o 2 como fallback)
        for anchor in ('\n### 1.2.', '\n## 2. FASE:', '\n---\n\n## 2.'):
            if anchor in content:
                return content.replace(anchor, f'\n\n{block}\n{anchor}', 1)
        return content.rstrip() + f'\n\n{block}\n'

    def _build_location_visibility_block(self, org_name: str,
                                          location: str, db_path) -> str:
        """
        Construye el bloque de visibilidad agregando TODOS los escaneos de una location.
        """
        import sqlite3 as _sq
        import ipaddress as _ipa
        from datetime import datetime as _dt

        conn = _sq.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sq.Row
        try:
            scans = conn.execute(
                """SELECT id, scan_mode, target_range, started_at, completed_at,
                          hosts_discovered, ports_found
                   FROM scans
                   WHERE UPPER(organization_name) = UPPER(?)
                     AND UPPER(location) = UPPER(?)
                     AND status = 'completed'
                   ORDER BY started_at""",
                (org_name, location)
            ).fetchall()
            if not scans:
                return ''

            # Redes registradas para la organización
            net_rows = conn.execute(
                """SELECT system_name, network_name, network_range
                   FROM networks
                   WHERE UPPER(organization_name) = UPPER(?)
                   ORDER BY system_name, network_name""",
                (org_name,)
            ).fetchall()
            known_nets = []
            for n in net_rows:
                try:
                    known_nets.append({
                        'obj':    _ipa.ip_network(n['network_range'], strict=False),
                        'name':   n['network_name'] or '—',
                        'system': n['system_name'] or '—',
                        'range':  n['network_range'],
                    })
                except ValueError:
                    pass

            # Agregar hosts y puertos de todos los escaneos de esta location
            all_hosts: Dict = {}   # ip → {hostname, mac, vendor}
            port_map:  Dict = {}   # ip → set of "port/svc"
            scan_stats = []        # lista de resúmenes por escaneo

            for s in scans:
                sid      = s['id']
                is_pass  = (s['scan_mode'] or 'active') == 'passive'

                # Duración
                dur = ''
                try:
                    if s['started_at'] and s['completed_at']:
                        st = _dt.fromisoformat(str(s['started_at'])[:19])
                        en = _dt.fromisoformat(str(s['completed_at'])[:19])
                        dur = f"{max(0, int((en - st).total_seconds() / 60))} min"
                except Exception:
                    pass

                if is_pass:
                    ip_rows = conn.execute(
                        """SELECT DISTINCT src_ip AS ip
                             FROM passive_conversations WHERE scan_id = ?
                           UNION
                           SELECT DISTINCT dst_ip AS ip
                             FROM passive_conversations WHERE scan_id = ?""",
                        (sid, sid)
                    ).fetchall()
                    h_count = len(ip_rows)
                    p_count = 0
                    for r in ip_rows:
                        all_hosts.setdefault(r['ip'], {
                            'hostname': None, 'mac_address': None, 'vendor': None})
                    for pr in conn.execute(
                        """SELECT DISTINCT dst_ip, dst_port, protocol
                             FROM passive_conversations
                            WHERE scan_id = ? AND dst_port IS NOT NULL""",
                        (sid,)
                    ).fetchall():
                        port_map.setdefault(pr['dst_ip'], set()).add(
                            f"{pr['dst_port']}/{pr['protocol'] or 'tcp'}"
                        )
                        p_count += 1
                else:
                    h_rows = conn.execute(
                        """SELECT DISTINCT h.ip_address, h.hostname,
                                  h.mac_address, h.vendor
                             FROM scan_results sr
                             JOIN hosts h ON h.id = sr.host_id
                            WHERE sr.scan_id = ?""",
                        (sid,)
                    ).fetchall()
                    h_count = len(h_rows)
                    p_count = 0
                    for h in h_rows:
                        ip = h['ip_address']
                        if ip not in all_hosts or (h['mac_address'] and
                                not all_hosts[ip]['mac_address']):
                            all_hosts[ip] = {
                                'hostname':    h['hostname'],
                                'mac_address': h['mac_address'],
                                'vendor':      h['vendor'],
                            }
                    for pr in conn.execute(
                        """SELECT h.ip_address, sr.port, sr.service_name
                             FROM scan_results sr
                             JOIN hosts h ON h.id = sr.host_id
                            WHERE sr.scan_id = ?
                              AND sr.port IS NOT NULL AND sr.state = 'open'""",
                        (sid,)
                    ).fetchall():
                        svc = pr['service_name'] or str(pr['port'])
                        port_map.setdefault(pr['ip_address'], set()).add(
                            f"{pr['port']}/{svc}"
                        )
                        p_count += 1

                scan_stats.append({
                    'id':      sid,
                    'date':    str(s['started_at'] or '')[:10],
                    'target':  s['target_range'] or '—',
                    'mode':    'Pasivo' if is_pass else 'Activo',
                    'hosts':   h_count,
                    'ports':   p_count,
                    'dur':     dur,
                })
        finally:
            conn.close()

        # Clasificar hosts en redes conocidas / desconocidas
        net_count: Dict = {}
        unknown:   Dict = {}
        for ip_str, hdata in sorted(all_hosts.items()):
            try:
                host_ip = _ipa.ip_address(ip_str)
            except ValueError:
                continue
            matched = False
            for n in known_nets:
                if host_ip in n['obj']:
                    net_count.setdefault(n['range'], {
                        'name': n['name'], 'system': n['system'],
                        'hosts': [], 'known': True,
                    })['hosts'].append(ip_str)
                    matched = True
                    break
            if not matched:
                parts = ip_str.rsplit('.', 1)
                subnet = f"{parts[0]}.0/24" if len(parts) == 2 else '0.0.0.0/0'
                unknown.setdefault(subnet, []).append(ip_str)

        total_hosts   = len(all_hosts)
        total_ports   = sum(len(v) for v in port_map.values())
        first_date    = scan_stats[0]['date'] if scan_stats else '—'
        last_date     = scan_stats[-1]['date'] if scan_stats else '—'
        period        = first_date if first_date == last_date else f"{first_date} → {last_date}"

        lines = [
            VISIBILIDAD_START,
            '#### 🔍 Visibilidad de Redes — ArsenalOT',
            '',
            f"**Vector de Acceso:** `{location}` · **Organización:** {org_name}  ",
            (f"**Escaneos realizados:** {len(scans)} · **Período:** {period}"
             f" · **Hosts únicos:** {total_hosts} · **Servicios totales:** {total_ports}"),
            '',
        ]

        # Tabla de escaneos
        lines += [
            '##### Escaneos desde este Origen',
            '',
            '| # | Fecha | Objetivo | Modo | Duración | Hosts | Servicios |',
            '|---:|:---|:---|:---|---:|---:|---:|',
        ]
        for ss in scan_stats:
            lines.append(
                f"| {ss['id']} | {ss['date']} | `{ss['target']}` | {ss['mode']}"
                f" | {ss['dur']} | {ss['hosts']} | {ss['ports']} |"
            )
        lines.append('')

        # Tabla de redes
        all_nets = (
            [{'range': r, **v} for r, v in net_count.items()] +
            [{'range': r, 'name': '—', 'system': '—', 'hosts': ips, 'known': False}
             for r, ips in unknown.items()]
        )
        if all_nets:
            all_nets.sort(key=lambda x: (not x['known'], x['range']))
            lines += [
                '##### Redes con Visibilidad',
                '',
                '| Red | Nombre | Sistema | Tipo | Hosts únicos |',
                '|:---|:---|:---|:---|---:|',
            ]
            for n in all_nets:
                tipo = '✅ Conocida' if n['known'] else '⚠️ Desconocida'
                lines.append(
                    f"| `{n['range']}` | {n['name']} | {n['system']}"
                    f" | {tipo} | {len(n['hosts'])} |"
                )
            lines.append('')

        # Tabla de hosts
        if all_hosts:
            lines += [
                '##### Hosts Descubiertos',
                '',
                '| IP | Hostname | MAC / Vendor | Servicios detectados |',
                '|:---|:---|:---|:---|',
            ]
            for ip_str in sorted(all_hosts,
                                  key=lambda x: tuple(int(p) for p in x.split('.')
                                                       if p.isdigit())):
                hd     = all_hosts[ip_str]
                hn     = hd.get('hostname') or '—'
                mac    = hd.get('mac_address') or ''
                vendor = hd.get('vendor') or ''
                if mac and vendor:
                    mac_str = f"{mac} / {vendor}"
                elif mac:
                    mac_str = mac
                elif vendor:
                    mac_str = vendor
                else:
                    mac_str = '—'
                ports   = sorted(port_map.get(ip_str, set()),
                                  key=lambda p: int(p.split('/')[0])
                                  if p.split('/')[0].isdigit() else 0)
                svc_str = ', '.join(ports[:8]) or '—'
                if len(ports) > 8:
                    svc_str += ', …'
                lines.append(f"| `{ip_str}` | `{hn}` | {mac_str} | {svc_str} |")
            lines.append('')

        lines.append(VISIBILIDAD_END)
        return '\n'.join(lines)

    def update_location_visibility(self, org_name: str, location: str,
                                    db_path) -> bool:
        """
        Actualiza el bloque ARSENAL:VISIBILIDAD de la nota del vector de acceso.
        Solo reemplaza ese bloque; el resto del documento queda intacto.
        """
        note_path = self._find_location_note_path(org_name, location)
        if note_path is None:
            return False
        block = self._build_location_visibility_block(org_name, location, db_path)
        if not block:
            return False
        content     = note_path.read_text(encoding='utf-8')
        new_content = self._inject_or_replace_visibility(content, block)
        if new_content != content:
            note_path.write_text(new_content, encoding='utf-8')
            _open_permissions(note_path)
        return True

    # ─────────────────────────────────────────────────────────
    # Creación automática desde vectores de acceso (location)
    # ─────────────────────────────────────────────────────────

    def create_location_note(self, org_name: str, location: str,
                              first_date: str) -> bool:
        """
        Crea la nota de bitácora para un vector de acceso (location).
        Nombre: YYYY-MM-DD - VE - {LOCATION}.md
        Devuelve True si la creó, False si ya existía.
        """
        file_title = f"{first_date} - VE - {location}"
        rel_path   = f"PENTEST IT OT/Bitacoras/{file_title}.md"

        org_dir = self.get_org_dir(org_name)
        if (org_dir / rel_path).exists():
            return False

        template_path = org_dir / "PENTEST IT OT/Plantillas/CHECKLIST-PENTEST.md"
        if not template_path.exists():
            template_path = TEMPLATE_DIR / "PENTEST IT OT/Plantillas/CHECKLIST-PENTEST.md"

        content = (template_path.read_text(encoding='utf-8')
                   if template_path.exists()
                   else f"# {file_title}\n\n")

        content = content.replace('<% tp.file.title %>', file_title)
        content = content.replace('`YYYY-MM-DD`', f'`{first_date}`', 1)
        content = content.replace(
            '| **Cliente / Objetivo** | `...` |',
            f'| **Cliente / Objetivo** | `{location}` |',
        )

        self.create_file(org_name, rel_path, content)
        return True

    def fill_from_scans(self, org_name: str, db_path) -> dict:
        """
        Crea/actualiza una nota por cada vector de acceso (location) con escaneos
        completados. No sobreescribe contenido manual fuera del bloque de visibilidad.
        Devuelve {created, skipped, errors}.
        """
        import sqlite3 as _sqlite3

        created = 0
        skipped = 0
        errors  = []

        conn = _sqlite3.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sqlite3.Row
        try:
            loc_rows = conn.execute(
                """SELECT location, MIN(started_at) AS first_scan
                   FROM scans
                   WHERE UPPER(organization_name) = UPPER(?) AND status = 'completed'
                   GROUP BY location
                   ORDER BY location""",
                (org_name,)
            ).fetchall()
        finally:
            conn.close()

        for lr in loc_rows:
            location   = lr['location']
            first_date = str(lr['first_scan'] or '')[:10]
            try:
                was_created = self.create_location_note(org_name, location, first_date)
                if was_created:
                    created += 1
                else:
                    skipped += 1
                self.update_location_visibility(org_name, location, db_path)
            except Exception as e:
                errors.append(f"{location}: {str(e)}")

        return {'created': created, 'skipped': skipped, 'errors': errors}

    # ─────────────────────────────────────────────────────────
    # Hallazgos (findings) — bloque gestionado en VULNERABILIDADES.md
    # ─────────────────────────────────────────────────────────

    FINDINGS_START = '<!-- ARSENAL:FINDINGS -->'
    FINDINGS_END   = '<!-- /ARSENAL:FINDINGS -->'

    def _get_vuln_note_path(self, org_name: str) -> Path:
        """Ruta de VULNERABILIDADES.md dentro de la org (la crea si no existe)."""
        org_dir   = self.get_org_dir(org_name)
        note_path = org_dir / "PENTEST IT OT" / "Bitacoras" / "NOTAS" / "VULNERABILIDADES.md"
        note_path.parent.mkdir(parents=True, exist_ok=True)
        _open_permissions(note_path.parent)
        if not note_path.exists():
            note_path.write_text(
                "# Vulnerabilidades\n\n"
                "> Notas sobre vulnerabilidades encontradas durante la evaluación.\n\n",
                encoding="utf-8"
            )
            _open_permissions(note_path)
        return note_path

    def add_finding_to_note(
        self,
        org_name: str,
        title: str,
        description: str = "",
        observation: str = "",
        remediation: str = "",
    ):
        """
        Añade un hallazgo al bloque ARSENAL:FINDINGS de VULNERABILIDADES.md.
        Si el bloque no existe, lo crea al final del archivo.
        Si ya existe un hallazgo con ese título, no lo duplica.
        """
        from datetime import datetime as _dt

        note_path = self._get_vuln_note_path(org_name)
        content   = note_path.read_text(encoding="utf-8")

        # Extraer bloque existente si hay uno
        if self.FINDINGS_START in content and self.FINDINGS_END in content:
            pre, rest  = content.split(self.FINDINGS_START, 1)
            block_body, post = rest.split(self.FINDINGS_END, 1)
        else:
            pre        = content.rstrip("\n") + "\n\n"
            block_body = ""
            post       = ""

        # Evitar duplicados (mismo título)
        if f"### {title}" in block_body:
            return

        # Construir entrada del hallazgo
        entry_lines = [f"### {title}", ""]
        if description:
            entry_lines += [f"**Descripción:** {description}", ""]
        if observation:
            entry_lines += [f"**Observación:** {observation}", ""]
        if remediation:
            entry_lines += [f"**Remediación:** {remediation}", ""]
        entry_lines.append("---")
        entry_lines.append("")
        entry = "\n".join(entry_lines)

        # Reconstruir bloque
        ts         = _dt.now().strftime("%Y-%m-%d %H:%M")
        new_block  = (
            f"\n## Hallazgos registrados (ArsenalOT)\n\n"
            + block_body.lstrip("\n")
            + entry
            + f"\n_Última actualización: {ts}_\n"
        )
        new_content = (
            pre
            + self.FINDINGS_START
            + new_block
            + self.FINDINGS_END
            + post
        )
        note_path.write_text(new_content, encoding="utf-8")
        _open_permissions(note_path)
