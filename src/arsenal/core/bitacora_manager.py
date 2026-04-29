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
import re
import shutil
import hashlib
import sqlite3
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

# Marcadores del bloque de evidencias web (screenshots + source code)
EVIDENCIAS_START = '<!-- ARSENAL:EVIDENCIAS -->'
EVIDENCIAS_END   = '<!-- /ARSENAL:EVIDENCIAS -->'

# Marcadores del bloque de imagen de diagrama de visibilidad
VIS_DIAGRAM_START = '<!-- ARSENAL:VISIBILIDAD-DIAGRAMA -->'
VIS_DIAGRAM_END   = '<!-- /ARSENAL:VISIBILIDAD-DIAGRAMA -->'

# Subcarpeta dentro de Bitacoras donde se copian las evidencias
EVIDENCIAS_SUBDIR = 'Evidencias'

# Subcarpeta dentro de Bitacoras donde se generan diagramas
DIAGRAMAS_SUBDIR = 'Diagramas'


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


def _format_purdue_level(level) -> str:
    if level is None:
        return '—'
    try:
        parsed = float(level)
    except (TypeError, ValueError):
        return str(level)
    return str(int(parsed)) if parsed.is_integer() else str(parsed)


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

        # Copiar .obsidian al directorio de la org para que funcione como vault
        # independiente con todos los plugins ya configurados.
        # Fuente preferida: .obsidian del vault raíz (tiene los plugins instalados por el
        # usuario); fallback: .obsidian del template del repo.
        org_obsidian = org_dir / ".obsidian"
        if not org_obsidian.exists():
            live_obsidian = self.vault_root / ".obsidian"
            obsidian_src = live_obsidian if live_obsidian.exists() else TEMPLATE_DIR / ".obsidian"
            if obsidian_src.exists():
                shutil.copytree(obsidian_src, org_obsidian)
                # workspace.json específico de cada vault — borrarlo para que
                # Obsidian genere uno limpio al abrir la carpeta
                ws = org_obsidian / "workspace.json"
                if ws.exists():
                    ws.unlink()
                _open_permissions(org_obsidian)

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
        """Devuelve la ruta del directorio de la org (creándola si no existe).
        También garantiza que tenga .obsidian/ por si fue creada antes de este fix."""
        org_dir = self.orgs_root / org_name
        if not org_dir.exists():
            self.create_org_bitacora(org_name)
        else:
            # Backfill: orgs creadas antes del fix no tienen .obsidian/
            org_obsidian = org_dir / ".obsidian"
            if not org_obsidian.exists():
                live_obsidian = self.vault_root / ".obsidian"
                obsidian_src = live_obsidian if live_obsidian.exists() else TEMPLATE_DIR / ".obsidian"
                if obsidian_src.exists():
                    shutil.copytree(obsidian_src, org_obsidian)
                    ws = org_obsidian / "workspace.json"
                    if ws.exists():
                        ws.unlink()
                    _open_permissions(org_obsidian)
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

    def get_guides_tree(self) -> List[Dict]:
        """Devuelve solo las guias del template maestro, sin plantillas ni bitacoras."""
        roots = [
            ("infra", "Pentest infraestructura", TEMPLATE_DIR / "PENTEST IT OT" / "Guías"),
            ("devices-62443", "Dispositivos IEC 62443", TEMPLATE_DIR / "EV. DISPOSITIVOS" / "62443" / "Guías"),
        ]
        tree = []
        for key, title, root in roots:
            if root.exists():
                tree.append({
                    "name": title,
                    "path": key,
                    "type": "dir",
                    "children": self._build_tree(root, root, key),
                })
        return tree

    def read_guide_file(self, guide_path: str) -> Tuple[str, float]:
        """Lee una guia del template maestro de forma segura."""
        guide_roots = {
            "infra": TEMPLATE_DIR / "PENTEST IT OT" / "Guías",
            "devices-62443": TEMPLATE_DIR / "EV. DISPOSITIVOS" / "62443" / "Guías",
        }
        parts = guide_path.replace("\\", "/").split("/", 1)
        if len(parts) != 2 or parts[0] not in guide_roots:
            raise FileNotFoundError(f"Guia no encontrada: {guide_path}")
        fpath = _safe_path(guide_roots[parts[0]], parts[1])
        if not fpath.exists() or not fpath.is_file():
            raise FileNotFoundError(f"Guia no encontrada: {guide_path}")
        return fpath.read_text(encoding="utf-8", errors="replace"), fpath.stat().st_mtime

    def get_bitacora_manifest(self, org_name: str, audit_type: str = "infra") -> Dict:
        """
        Devuelve la vista de bitacora editable para ArsenalOT, separada de guias
        y plantillas. No modifica la estructura del vault, solo filtra la vista.
        """
        root_rel = self._bitacora_root_rel(audit_type)
        org_dir = self.get_org_dir(org_name)
        root = org_dir / root_rel
        root.mkdir(parents=True, exist_ok=True)
        _open_permissions(root)

        notes_dir = root / "NOTAS"
        notes_dir.mkdir(parents=True, exist_ok=True)
        _open_permissions(notes_dir)

        fixed_notes = [
            ("general", "General", "GENERAL.md", "# General\n\n"),
            ("vulnerabilities", "Vulnerabilidades", "VULNERABILIDADES.md", "# Vulnerabilidades\n\n"),
            ("candidates", "Candidatos", "CANDIDATOS.md", "# Candidatos\n\n"),
            ("credentials", "Credenciales", "CREDENCIALES.md", "## IT\n\n## OT\n"),
        ]
        fixed = []
        for key, label, filename, initial_content in fixed_notes:
            note = notes_dir / filename
            if not note.exists():
                note.write_text(initial_content, encoding="utf-8")
                _open_permissions(note)
            fixed.append({
                "key": key,
                "label": label,
                "path": (Path(root_rel) / "NOTAS" / filename).as_posix(),
            })

        sources = []
        for note in sorted(root.glob("*.md"), key=lambda p: p.name.lower()):
            sources.append({
                "label": note.stem,
                "path": (Path(root_rel) / note.name).as_posix(),
                "mtime": note.stat().st_mtime,
            })

        return {
            "audit_type": audit_type if audit_type in {"infra", "device"} else "infra",
            "root": Path(root_rel).as_posix(),
            "sources": sources,
            "fixed_notes": fixed,
        }

    @staticmethod
    def _bitacora_root_rel(audit_type: str = "infra") -> str:
        if audit_type == "device":
            return "EV. DISPOSITIVOS/62443/Bitacoras"
        return "PENTEST IT OT/Bitacoras"

    def _build_tree(self, base: Path, root: Path, path_prefix: str = "") -> List[Dict]:
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
            rel_with_prefix = f"{path_prefix}/{rel}" if path_prefix else rel
            if entry.is_dir():
                children = self._build_tree(entry, root, path_prefix)
                nodes.append({"name": entry.name, "path": rel_with_prefix, "type": "dir", "children": children})
            else:
                stat = entry.stat()
                nodes.append({
                    "name": entry.name,
                    "path": rel_with_prefix,
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

    # ── Sufijo de IP en nombre de nota ──
    @staticmethod
    def _ip_label(myip: Optional[str]) -> str:
        """Devuelve la etiqueta de IP que aparece entre paréntesis en el nombre."""
        ip = (myip or '').strip()
        return ip if ip else 'sin IP'

    @classmethod
    def _note_basename(cls, location: str, myip: Optional[str]) -> str:
        """`VE - LOCATION (IP)` o `VE - LOCATION (sin IP)`."""
        return f"VE - {location} ({cls._ip_label(myip)})"

    def _find_location_note_path(self, org_name: str, location: str,
                                  myip: Optional[str] = None) -> Optional[Path]:
        """
        Localiza el .md de un vector de acceso (location, myip) en Bitacoras/.

        Busca exclusivamente la nota correspondiente al sufijo de IP
        (`*VE - LOCATION (IP).md` o `*VE - LOCATION (sin IP).md` cuando
        ``myip`` es None/'').

        No hace fallback a notas legacy sin sufijo: si la nota antigua existe
        y no se ha migrado, debe migrarse explícitamente con
        :meth:`_migrate_legacy_note`. De lo contrario, los flujos
        segmentados por IP escribirían sobre el mismo fichero.

        Si existen varias coincidencias, devuelve la más antigua (orden
        alfabético = cronológico dado el prefijo YYYY-MM-DD).
        """
        bitacoras = self.get_org_dir(org_name) / "PENTEST IT OT" / "Bitacoras"
        if not bitacoras.exists():
            return None

        label = self._ip_label(myip)
        hits = sorted(bitacoras.glob(f"*VE - {location} ({label}).md"))
        return hits[0] if hits else None

    def _find_legacy_location_note_path(self, org_name: str,
                                         location: str) -> Optional[Path]:
        """Devuelve la nota legacy (`*VE - LOCATION.md`, sin sufijo IP) si existe."""
        bitacoras = self.get_org_dir(org_name) / "PENTEST IT OT" / "Bitacoras"
        if not bitacoras.exists():
            return None
        hits = sorted(bitacoras.glob(f"*VE - {location}.md"))
        return hits[0] if hits else None

    def rename_location_notes(self, org_name: str, old_location: str,
                              new_location: str) -> Dict[str, int]:
        """
        Renombra las notas de bitácora asociadas a un origen.

        Conserva el prefijo de fecha y el sufijo de IP, y evita sobrescribir
        notas existentes. El contenido manual se mantiene; solo se reemplazan
        referencias directas al nombre antiguo dentro del fichero renombrado.
        """
        old_location = (old_location or '').strip().upper()
        new_location = (new_location or '').strip().upper()
        stats = {"matched": 0, "renamed": 0, "conflicts": 0}
        if not old_location or not new_location or old_location == new_location:
            return stats

        bitacoras = self.get_org_dir(org_name) / "PENTEST IT OT" / "Bitacoras"
        if not bitacoras.exists():
            return stats

        for note_path in sorted(bitacoras.glob("*.md")):
            if " - VE - " not in note_path.stem:
                continue
            prefix, location_part = note_path.stem.split(" - VE - ", 1)
            location_upper = location_part.upper()
            if location_upper != old_location and not location_upper.startswith(f"{old_location} ("):
                continue

            stats["matched"] += 1
            suffix = location_part[len(old_location):]
            new_name = f"{prefix} - VE - {new_location}{suffix}.md"
            new_path = note_path.with_name(new_name)
            if new_path.exists() and new_path != note_path:
                stats["conflicts"] += 1
                continue

            content = note_path.read_text(encoding='utf-8')
            old_escaped = re.escape(old_location)
            new_content = re.sub(
                rf"VE - {old_escaped}",
                f"VE - {new_location}",
                content,
                flags=re.IGNORECASE,
            )
            new_content = re.sub(
                rf"`{old_escaped}`",
                f"`{new_location}`",
                new_content,
                flags=re.IGNORECASE,
            )
            new_content = re.sub(
                rf"{old_escaped} \(",
                f"{new_location} (",
                new_content,
                flags=re.IGNORECASE,
            )

            if new_content != content:
                note_path.write_text(new_content, encoding='utf-8')

            if new_path != note_path:
                note_path.rename(new_path)
                _open_permissions(new_path)
                stats["renamed"] += 1
            else:
                _open_permissions(note_path)

        return stats

    # Orden y etiquetas de las técnicas de descubrimiento. La capa indica
    # qué tipo de visibilidad implica desde el origen hasta el segmento:
    # L2 (mismo dominio de broadcast) vs L3 (alcance enrutado) vs L7.
    _TECHNIQUE_ORDER = ('arp', 'ping', 'ports', 'web', 'ioxid')
    _TECHNIQUE_LABELS = {
        'arp':     'ARP (L2)',
        'ping':    'Ping (L3)',
        'ports':   'Ports (L3)',
        'web':     'Web (L7)',
        'ioxid':   'IOXID (L7)',
    }

    @staticmethod
    def _method_to_technique(discovery_method: Optional[str], has_mac: bool,
                              has_port: bool = False) -> Optional[str]:
        """
        Traduce ``scan_results.discovery_method`` a una técnica de descubrimiento
        normalizada. ``has_mac`` desambigua el valor legacy ``host_discovery``
        (Phase 1 antes de separar ARP e ICMP): con MAC ⇒ ARP (L2);
        sin MAC ⇒ ICMP/ping (L3).
        """
        m = (discovery_method or '').lower()
        if m == 'arp_discovery':
            return 'arp'
        if m == 'icmp_discovery':
            return 'ping'
        if m == 'host_discovery':
            return 'arp' if has_mac else 'ping'
        if m == 'nmap_ping':
            return 'ping'
        if m == 'nmap_ports':
            # Si el registro de nmap_ports no tiene puerto es un host marcado
            # 'up' por nmap (ping efectivo); con puerto sí implica L3 + servicio.
            return 'ports' if has_port else 'ping'
        if m == 'specific_capture':
            return 'web'
        if m == 'ioxid':
            return 'ioxid'
        # 'enrichment', 'imported', 'nmap_import' no son técnicas de
        # descubrimiento de visibilidad propias — se omiten.
        return None

    @classmethod
    def _format_techniques(cls, techs: set) -> str:
        """Renderiza un conjunto de técnicas en el orden canónico."""
        if not techs:
            return '—'
        labels = [cls._TECHNIQUE_LABELS[t] for t in cls._TECHNIQUE_ORDER if t in techs]
        # Conservar técnicas desconocidas (defensive) al final
        labels += [t for t in sorted(techs) if t not in cls._TECHNIQUE_LABELS]
        return ' · '.join(labels) if labels else '—'

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
            if (scan['scan_mode'] or 'active') == 'passive':
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

        mode_lbl   = 'Activo'
        origin_lbl = f"Escaneo {scan_id}"
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

    @staticmethod
    def _metadata_placeholder(value: str) -> bool:
        cleaned = re.sub(r'[`*_]', '', str(value or '')).strip().strip('|').strip()
        return cleaned in {'', '...', '-', '—', 'N/A', 'n/a', 'None', 'none'}

    @staticmethod
    def _metadata_value(values) -> Optional[str]:
        if values is None:
            return None
        if isinstance(values, (list, tuple, set)):
            cleaned = []
            for value in values:
                text = str(value or '').strip()
                if text and text not in cleaned:
                    cleaned.append(text)
            if not cleaned:
                return None
            return ', '.join(cleaned)
        text = str(values or '').strip()
        return text or None

    def _collect_location_note_metadata(self, org_name: str, location: str,
                                        db_path,
                                        myip: Optional[str] = None) -> Dict[str, str]:
        """Obtiene metadatos conocidos para rellenar la cabecera de una nota."""
        import sqlite3 as _sq

        ip_filter = (myip or '').strip() or None
        conn = _sq.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sq.Row
        try:
            query = """SELECT target_range, interface, myip, started_at, created_by
                       FROM scans
                       WHERE UPPER(organization_name) = UPPER(?)
                         AND UPPER(location) = UPPER(?)
                         AND COALESCE(scan_mode, 'active') != 'passive'"""
            params = [org_name, location]
            if ip_filter is not None:
                query += " AND myip = ?"
                params.append(ip_filter)
            else:
                query += " AND (myip IS NULL OR myip = '')"
            query += " ORDER BY started_at ASC"
            rows = conn.execute(query, params).fetchall()
        finally:
            conn.close()

        if not rows:
            return {}

        target_ranges = [row['target_range'] for row in rows if row['target_range']]
        interfaces = [row['interface'] for row in rows if row['interface']]
        attacker_ips = [row['myip'] for row in rows if row['myip']]
        testers = [row['created_by'] for row in rows if row['created_by']]
        first_date = str(rows[0]['started_at'] or '')[:10]
        cliente_label = (f"{location} ({self._ip_label(myip)})"
                         if (myip or '').strip() else location)

        metadata = {
            "Cliente / Objetivo": cliente_label,
            "Fecha de Inicio": first_date,
            "Tester(s)": self._metadata_value(testers),
            "Interfaz de Ataque": self._metadata_value(interfaces),
            "IP Atacante": self._metadata_value(attacker_ips or ([myip] if myip else [])),
            "Rango Objetivo": self._metadata_value(target_ranges),
        }
        return {key: value for key, value in metadata.items() if value}

    def _update_metadata_table(self, content: str, metadata: Dict[str, str]) -> str:
        """Rellena filas conocidas de la tabla de metadatos sin pisar valores manuales."""
        if not metadata:
            return content

        aliases = {
            "Cliente / Objetivo": ["Cliente / Objetivo"],
            "Fecha de Inicio": ["Fecha de Inicio"],
            "Tester(s)": ["Tester(s)", "Testers", "Tester"],
            "Interfaz de Ataque": ["Interfaz de Ataque"],
            "IP Atacante": ["IP Atacante"],
            "Rango Objetivo": ["Rango Objetivo", "Rango(s) Objetivo", "Objetivo"],
        }
        updated = content
        for canonical, labels in aliases.items():
            value = metadata.get(canonical)
            if not value:
                continue
            for label in labels:
                pattern = re.compile(
                    rf"(^\|\s*\*\*{re.escape(label)}\*\*\s*\|\s*)(.*?)\s*(\|\s*$)",
                    re.MULTILINE,
                )

                def repl(match):
                    current = match.group(2)
                    if not self._metadata_placeholder(current):
                        return match.group(0)
                    return f"{match.group(1)}`{value}` {match.group(3)}"

                updated, count = pattern.subn(repl, updated, count=1)
                if count:
                    break
        return updated

    def update_location_metadata(self, org_name: str, location: str, db_path,
                                 myip: Optional[str] = None) -> bool:
        """Actualiza la tabla superior de metadatos de una nota de origen."""
        note_path = self._find_location_note_path(org_name, location, myip)
        if note_path is None:
            return False
        metadata = self._collect_location_note_metadata(org_name, location, db_path, myip)
        if not metadata:
            return False
        content = note_path.read_text(encoding='utf-8')
        new_content = self._update_metadata_table(content, metadata)
        if new_content == content:
            return False
        note_path.write_text(new_content, encoding='utf-8')
        _open_permissions(note_path)
        return True

    def _diagrams_dir(self, org_name: str) -> Path:
        """Carpeta destino para diagramas generados dentro de la bitacora."""
        dpath = (self.get_org_dir(org_name)
                 / "PENTEST IT OT" / "Bitacoras" / DIAGRAMAS_SUBDIR)
        dpath.mkdir(parents=True, exist_ok=True)
        _open_permissions(dpath)
        return dpath

    @staticmethod
    def _slug_filename(value: str) -> str:
        cleaned = re.sub(r'[^A-Za-z0-9._-]+', '_', value or '').strip('._-')
        return cleaned[:120] or 'origen'

    def _collect_location_visibility_data(self, org_name: str, location: str,
                                          db_path,
                                          myip: Optional[str] = None) -> Optional[Dict]:
        """Recoge los datos agregados de visibilidad usados por la imagen."""
        import sqlite3 as _sq
        import ipaddress as _ipa

        ip_filter = (myip or '').strip() or None
        conn = _sq.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sq.Row
        try:
            base_q = """SELECT id, target_range, started_at
                       FROM scans
                       WHERE UPPER(organization_name) = UPPER(?)
                         AND UPPER(location) = UPPER(?)
                         AND status = 'completed'
                         AND COALESCE(scan_mode, 'active') != 'passive'"""
            params = [org_name, location]
            if ip_filter is not None:
                base_q += " AND myip = ?"
                params.append(ip_filter)
            else:
                base_q += " AND (myip IS NULL OR myip = '')"
            base_q += " ORDER BY started_at"
            scans = conn.execute(base_q, params).fetchall()
            if not scans:
                return None

            net_rows = conn.execute(
                """SELECT system_name, network_name, network_range, purdue_level
                   FROM networks
                   WHERE UPPER(organization_name) = UPPER(?)
                   ORDER BY system_name, network_name""",
                (org_name,)
            ).fetchall()
            known_nets = []
            for n in net_rows:
                try:
                    known_nets.append({
                        'obj': _ipa.ip_network(n['network_range'], strict=False),
                        'name': n['network_name'] or '-',
                        'system': n['system_name'] or 'Sin sistema',
                        'purdue': _format_purdue_level(n['purdue_level']) if n['purdue_level'] is not None else '-',
                        'range': n['network_range'],
                    })
                except ValueError:
                    pass

            critical_by_ip = {}
            for dev in conn.execute(
                """SELECT system_name, name, ips, reason
                   FROM critical_devices
                   WHERE UPPER(organization_name) = UPPER(?)""",
                (org_name,)
            ).fetchall():
                for ip_text in str(dev['ips'] or '').split(','):
                    ip_text = ip_text.strip()
                    if ip_text:
                        critical_by_ip.setdefault(ip_text, []).append({
                            'name': dev['name'] or '-',
                            'system': dev['system_name'] or '-',
                            'reason': dev['reason'] or '-',
                        })

            all_hosts: Dict[str, Dict] = {}
            host_techniques: Dict[str, set] = {}
            for scan in scans:
                for h in conn.execute(
                    """SELECT h.ip_address, h.hostname, h.mac_address, h.vendor,
                              sr.discovery_method, sr.port
                         FROM scan_results sr
                         JOIN hosts h ON h.id = sr.host_id
                        WHERE sr.scan_id = ?""",
                    (scan['id'],)
                ).fetchall():
                    ip = h['ip_address']
                    all_hosts.setdefault(ip, {
                        'hostname': h['hostname'],
                        'mac_address': h['mac_address'],
                        'vendor': h['vendor'],
                    })
                    tech = self._method_to_technique(
                        h['discovery_method'],
                        bool(h['mac_address']),
                        has_port=h['port'] is not None,
                    )
                    if tech:
                        host_techniques.setdefault(ip, set()).add(tech)
        finally:
            conn.close()

        def match_known_network(ip_str: str) -> Optional[Dict]:
            try:
                host_ip = _ipa.ip_address(ip_str)
            except ValueError:
                return None
            matches = [n for n in known_nets if host_ip in n['obj']]
            if not matches:
                return None
            return max(matches, key=lambda n: n['obj'].prefixlen)

        source_network = None
        if ip_filter:
            source_match = match_known_network(ip_filter)
            if source_match:
                source_network = {
                    'range': source_match['range'],
                    'name': source_match['name'],
                    'system': source_match['system'],
                    'purdue': source_match['purdue'],
                    'known': True,
                    'hosts': [ip_filter],
                    'techniques': set(),
                    'critical': [],
                }
            else:
                parts = ip_filter.rsplit('.', 1)
                source_network = {
                    'range': f"{parts[0]}.0/24" if len(parts) == 2 else '0.0.0.0/0',
                    'name': 'Red origen no registrada',
                    'system': 'Unknown',
                    'purdue': '-',
                    'known': False,
                    'hosts': [ip_filter],
                    'techniques': set(),
                    'critical': [],
                }

        networks: Dict[str, Dict] = {}
        for ip_str in sorted(all_hosts.keys()):
            try:
                host_ip = _ipa.ip_address(ip_str)
            except ValueError:
                continue
            matched = match_known_network(ip_str)
            if matched:
                key = matched['range']
                item = networks.setdefault(key, {
                    'range': matched['range'],
                    'name': matched['name'],
                    'system': matched['system'],
                    'purdue': matched['purdue'],
                    'known': True,
                    'hosts': [],
                    'techniques': set(),
                    'critical': [],
                })
            else:
                parts = ip_str.rsplit('.', 1)
                key = f"{parts[0]}.0/24" if len(parts) == 2 else '0.0.0.0/0'
                item = networks.setdefault(key, {
                    'range': key,
                    'name': 'Red no registrada',
                    'system': 'Sin sistema',
                    'purdue': '-',
                    'known': False,
                    'hosts': [],
                    'techniques': set(),
                    'critical': [],
                })
            item['hosts'].append(ip_str)
            item['techniques'].update(host_techniques.get(ip_str, set()))
            item['critical'].extend(critical_by_ip.get(ip_str, []))

        network_list = list(networks.values())
        network_list.sort(key=lambda n: (n['system'].lower(), not n['known'], n['range']))
        return {
            'org_name': org_name,
            'location': location,
            'myip': ip_filter or 'sin IP',
            'scan_count': len(scans),
            'first_date': str(scans[0]['started_at'] or '')[:10],
            'last_date': str(scans[-1]['started_at'] or '')[:10],
            'host_count': len(all_hosts),
            'source_network': source_network,
            'networks': network_list,
        }

    def _draw_text_wrapped(self, draw, text: str, xy: Tuple[int, int],
                           font, fill, max_width: int, line_spacing: int = 4,
                           max_lines: Optional[int] = None) -> int:
        words = str(text or '').split()
        lines = []
        current = ''
        for word in words:
            candidate = f"{current} {word}".strip()
            if draw.textbbox((0, 0), candidate, font=font)[2] <= max_width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines]
            while lines[-1] and draw.textbbox((0, 0), lines[-1] + '...', font=font)[2] > max_width:
                lines[-1] = lines[-1][:-1]
            lines[-1] = lines[-1] + '...'
        x, y = xy
        for line in lines:
            draw.text((x, y), line, font=font, fill=fill)
            bbox = draw.textbbox((x, y), line, font=font)
            y += (bbox[3] - bbox[1]) + line_spacing
        return y

    def _render_visibility_diagram_png(self, data: Dict, output_path: Path) -> None:
        """Genera un PNG claro siguiendo el formato visual del diagrama de resultados."""
        from PIL import Image, ImageDraw, ImageFont

        def font(size: int, bold: bool = False):
            candidates = (
                ["arialbd.ttf", "Arial Bold.ttf", "DejaVuSans-Bold.ttf"] if bold
                else ["arial.ttf", "Arial.ttf", "DejaVuSans.ttf"]
            )
            for candidate in candidates:
                try:
                    return ImageFont.truetype(candidate, size)
                except OSError:
                    continue
            return ImageFont.load_default()

        title_font = font(28, True)
        system_font = font(16, True)
        card_title_font = font(15, True)
        body_font = font(13)
        small_font = font(11)
        networks = data.get('networks') or []
        source_network = data.get('source_network') or {
            'name': data['location'],
            'range': data['myip'],
            'system': 'Origen',
            'known': False,
            'hosts': [data['myip']],
            'critical': [],
        }

        source_system = source_network.get('system') or 'Unknown'
        grouped_targets: Dict[str, List[Dict]] = {}
        for net in networks:
            grouped_targets.setdefault(net.get('system') or 'Unknown', []).append(net)

        card_w = 238
        card_h = 84
        card_gap = 14
        sys_pad_x = 18
        sys_pad_top = 36
        sys_pad_bottom = 18
        sys_gap_x = 64
        top = 142
        left = 42
        source_box_w = 286
        source_box_h = sys_pad_top + card_h + sys_pad_bottom

        target_systems = sorted(grouped_targets.items(), key=lambda item: (item[0].lower() == 'unknown', item[0].lower()))
        target_box_sizes = []
        for system_name, system_networks in target_systems:
            rows = max(1, len(system_networks))
            height = sys_pad_top + rows * card_h + (rows - 1) * card_gap + sys_pad_bottom
            target_box_sizes.append((system_name, system_networks, 302, height))

        width = max(1180, left + source_box_w + sys_gap_x + sum(w + sys_gap_x for _, _, w, _ in target_box_sizes) + 40)
        height = max(640, top + max([source_box_h] + [h for _, _, _, h in target_box_sizes] + [130]) + 72)

        image = Image.new('RGB', (width, height), '#edf1f7')
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((20, 18, width - 20, 104), radius=18, fill='#f0f4ff', outline='#d7e1f4', width=1)
        draw.text((42, 34), f"Diagrama de visibilidad - {data['location']}", font=title_font, fill='#0f172a')
        subtitle = f"Organizacion: {data['org_name']} · Filtro origen: {data['myip']} · Escaneos: {data['scan_count']} · Hosts visibles: {data['host_count']}"
        draw.text((44, 78), subtitle, font=body_font, fill='#475569')

        def system_rect(x: int, y: int, w: int, h: int, label: str, role: str = ''):
            outline = '#dc2626' if role == 'source' else ('#16a34a' if role == 'target' else '#5a84ce')
            draw.rounded_rectangle((x, y, x + w, y + h), radius=18, fill=None, outline=outline, width=2)
            draw.rounded_rectangle((x + 14, y - 12, x + 14 + min(220, max(78, len(label) * 9)), y + 14), radius=8, fill='#f0f4ff')
            draw.text((x + 22, y - 8), label, font=system_font, fill='#1a2035')

        def network_card(x: int, y: int, net: Dict, role: str = '', count_text: str = '') -> Tuple[int, int, int, int]:
            if role == 'source':
                fill, outline = '#fff1f2', '#dc2626'
            elif role == 'target':
                fill, outline = '#f0fdf4', '#16a34a'
            else:
                fill, outline = '#f5f8ff', '#5a84ce'
            box = (x, y, x + card_w, y + card_h)
            draw.rounded_rectangle(box, radius=15, fill=fill, outline=outline, width=2)
            draw.ellipse((x - 7, y + card_h // 2 - 6, x + 5, y + card_h // 2 + 6), fill=fill, outline=outline, width=2)
            draw.ellipse((x + card_w - 5, y + card_h // 2 - 6, x + card_w + 7, y + card_h // 2 + 6), fill=fill, outline=outline, width=2)
            title = net.get('name') or net.get('range') or '-'
            self._draw_text_wrapped(draw, title, (x + 14, y + 11), card_title_font, '#0f172a', card_w - 82, max_lines=2)
            if count_text:
                badge_w = max(44, min(74, len(count_text) * 8 + 18))
                draw.rounded_rectangle((x + card_w - badge_w - 12, y + 10, x + card_w - 12, y + 30), radius=10, fill='#ede9fe', outline='#a78bfa')
                draw.text((x + card_w - badge_w - 2, y + 14), count_text, font=small_font, fill='#5b21b6')
            draw.text((x + 14, y + 47), str(net.get('range') or '-'), font=small_font, fill='#475569')
            badge = 'Origen' if role == 'source' else ('Desde ' + str(data['myip']) if role == 'target' else '')
            if badge:
                badge_fill = '#fee2e2' if role == 'source' else '#dcfce7'
                badge_text = '#991b1b' if role == 'source' else '#15803d'
                draw.rounded_rectangle((x + 14, y + 62, x + card_w - 14, y + 78), radius=8, fill=badge_fill)
                self._draw_text_wrapped(draw, badge, (x + 22, y + 64), small_font, badge_text, card_w - 44, max_lines=1)
            if net.get('critical'):
                draw.text((x + card_w - 28, y + 58), "★", font=card_title_font, fill='#7c3aed')
            return box

        source_x = left
        source_y = top + max(0, (height - top - 90 - source_box_h) // 2)
        source_card = (
            source_x + sys_pad_x,
            source_y + sys_pad_top,
            source_x + sys_pad_x + card_w,
            source_y + sys_pad_top + card_h,
        )
        target_layouts = []
        target_x = source_x + source_box_w + sys_gap_x
        for system_name, system_networks, box_w, box_h in target_box_sizes:
            target_y = top + max(0, (height - top - 90 - box_h) // 2)
            cards = []
            for idx, net in enumerate(system_networks):
                card_y = target_y + sys_pad_top + idx * (card_h + card_gap)
                cards.append({
                    'network': net,
                    'box': (
                        target_x + sys_pad_x,
                        card_y,
                        target_x + sys_pad_x + card_w,
                        card_y + card_h,
                    ),
                })
            target_layouts.append({
                'system_name': system_name,
                'x': target_x,
                'y': target_y,
                'width': box_w,
                'height': box_h,
                'cards': cards,
            })
            target_x += box_w + sys_gap_x

        def draw_visibility_route(source_box, target_box, lane_index: int):
            source_anchor = (source_box[2] + 7, source_box[1] + (source_box[3] - source_box[1]) // 2)
            target_anchor = (target_box[0] - 7, target_box[1] + (target_box[3] - target_box[1]) // 2)
            system_tops = [source_y] + [layout['y'] for layout in target_layouts]
            lane_y = max(112, min(system_tops or [top]) - 22 - ((lane_index % 3) * 8))
            source_gutter_x = source_box[2] + 26
            target_gutter_x = target_box[0] - 26
            points = [
                source_anchor,
                (source_gutter_x, source_anchor[1]),
                (source_gutter_x, lane_y),
                (target_gutter_x, lane_y),
                (target_gutter_x, target_anchor[1]),
                target_anchor,
            ]
            draw.line(points, fill='#67a7c9', width=3, joint='curve')
            draw.ellipse(
                (target_anchor[0] - 4, target_anchor[1] - 4,
                 target_anchor[0] + 4, target_anchor[1] + 4),
                fill='#67a7c9',
            )

        if not target_systems:
            system_rect(source_x, source_y, source_box_w, source_box_h, source_system, 'source')
            network_card(source_card[0], source_card[1], source_network, 'source')
            empty_box = (source_x + source_box_w + sys_gap_x, top + 70, width - 70, top + 190)
            draw.rounded_rectangle(empty_box, radius=16, fill='#ffffff', outline='#cbd5e1', width=2)
            draw.text((empty_box[0] + 24, empty_box[1] + 46), "Sin destinos con visibilidad registrada para este origen.", font=system_font, fill='#334155')
        else:
            route_index = 0
            for layout in target_layouts:
                for card in layout['cards']:
                    draw_visibility_route(source_card, card['box'], route_index)
                    route_index += 1

            system_rect(source_x, source_y, source_box_w, source_box_h, source_system, 'source')
            network_card(source_card[0], source_card[1], source_network, 'source')
            for layout in target_layouts:
                system_rect(layout['x'], layout['y'], layout['width'], layout['height'], layout['system_name'], 'target')
                for card in layout['cards']:
                    net = card['network']
                    count_text = f"{len(net.get('hosts') or [])}/{max(1, len(net.get('hosts') or []))}"
                    network_card(card['box'][0], card['box'][1], net, 'target', count_text)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        image.save(output_path, 'PNG', optimize=True)
        _open_permissions(output_path)

    def _build_visibility_diagram_block(self, rel_image_path: str, data: Dict) -> str:
        period = data['first_date'] if data['first_date'] == data['last_date'] else f"{data['first_date']} -> {data['last_date']}"
        return '\n'.join([
            VIS_DIAGRAM_START,
            '#### Diagrama de Visibilidad - ArsenalOT',
            '',
            f"![Diagrama de visibilidad del origen {data['location']}]({rel_image_path})",
            '',
            f"_Imagen en modo claro actualizada desde ArsenalOT. Periodo: {period}._",
            VIS_DIAGRAM_END,
        ])

    def _inject_or_replace_visibility_diagram(self, content: str, block: str) -> str:
        if VIS_DIAGRAM_START in content and VIS_DIAGRAM_END in content:
            s = content.index(VIS_DIAGRAM_START)
            e = content.index(VIS_DIAGRAM_END) + len(VIS_DIAGRAM_END)
            return content[:s] + block + content[e:]
        if VISIBILIDAD_START in content:
            return content.replace(VISIBILIDAD_START, f"{block}\n\n{VISIBILIDAD_START}", 1)
        return content.rstrip() + f'\n\n{block}\n'

    def update_location_visibility_diagram(self, org_name: str, location: str,
                                           db_path,
                                           myip: Optional[str] = None) -> bool:
        """Genera/actualiza la imagen clara del diagrama en la nota del origen."""
        note_path = self._find_location_note_path(org_name, location, myip)
        if note_path is None:
            return False
        data = self._collect_location_visibility_data(org_name, location, db_path, myip)
        if not data:
            return False
        label = self._ip_label(myip)
        image_name = f"visibilidad_{self._slug_filename(location)}_{self._slug_filename(label)}.png"
        image_path = self._diagrams_dir(org_name) / image_name
        self._render_visibility_diagram_png(data, image_path)
        rel_image_path = f"{DIAGRAMAS_SUBDIR}/{image_name}"
        block = self._build_visibility_diagram_block(rel_image_path, data)
        content = note_path.read_text(encoding='utf-8')
        new_content = self._inject_or_replace_visibility_diagram(content, block)
        if new_content != content:
            note_path.write_text(new_content, encoding='utf-8')
            _open_permissions(note_path)
        return True

    def refresh_org_visibility_diagrams(self, org_name: str, db_path) -> Dict:
        """Actualiza diagramas y bloques de visibilidad de todos los origenes existentes."""
        import sqlite3 as _sq

        conn = _sq.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sq.Row
        try:
            rows = conn.execute(
                """SELECT location,
                          CASE WHEN myip IS NULL OR myip = '' THEN NULL ELSE myip END AS myip,
                          MIN(started_at) AS first_scan
                   FROM scans
                   WHERE UPPER(organization_name) = UPPER(?)
                     AND status = 'completed'
                     AND COALESCE(scan_mode, 'active') != 'passive'
                   GROUP BY location, CASE WHEN myip IS NULL OR myip = '' THEN NULL ELSE myip END
                   ORDER BY location, myip""",
                (org_name,)
            ).fetchall()
        finally:
            conn.close()

        updated = 0
        for row in rows:
            location = row['location']
            myip = row['myip']
            first_date = str(row['first_scan'] or '')[:10]
            self.create_location_note(org_name, location, first_date, myip)
            if self.update_location_visibility(org_name, location, db_path, myip):
                updated += 1
            elif self.update_location_visibility_diagram(org_name, location, db_path, myip):
                updated += 1
        return {"diagramas_actualizados": updated, "origenes": len(rows)}

    def _build_location_visibility_block(self, org_name: str,
                                          location: str, db_path,
                                          myip: Optional[str] = None) -> str:
        """
        Construye el bloque de visibilidad agregando los escaneos de una
        location. Si se proporciona ``myip``, sólo agrega los escaneos
        ejecutados desde esa IP (o sin IP cuando ``myip`` es None/'').
        """
        import sqlite3 as _sq
        import ipaddress as _ipa
        from datetime import datetime as _dt

        ip_filter = (myip or '').strip() or None

        conn = _sq.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sq.Row
        try:
            base_q = """SELECT id, scan_mode, target_range, started_at, completed_at,
                              hosts_discovered, ports_found
                       FROM scans
                       WHERE UPPER(organization_name) = UPPER(?)
                         AND UPPER(location) = UPPER(?)
                         AND status = 'completed'
                         AND COALESCE(scan_mode, 'active') != 'passive'"""
            params = [org_name, location]
            if ip_filter is not None:
                base_q += " AND myip = ?"
                params.append(ip_filter)
            else:
                base_q += " AND (myip IS NULL OR myip = '')"
            base_q += " ORDER BY started_at"
            scans = conn.execute(base_q, params).fetchall()
            if not scans:
                return ''

            # Redes registradas para la organización
            net_rows = conn.execute(
                """SELECT system_name, network_name, network_range, purdue_level
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
                        'purdue': _format_purdue_level(n['purdue_level']) if n['purdue_level'] is not None else '—',
                        'range':  n['network_range'],
                    })
                except ValueError:
                    pass

            critical_rows = conn.execute(
                """SELECT system_name, name, ips, reason
                   FROM critical_devices
                   WHERE UPPER(organization_name) = UPPER(?)
                   ORDER BY system_name, name""",
                (org_name,)
            ).fetchall()

            # Agregar hosts y puertos de todos los escaneos de esta location
            all_hosts: Dict = {}   # ip → {hostname, mac, vendor}
            port_map:  Dict = {}   # ip → set of "port/svc"
            host_techniques: Dict[str, set] = {}  # ip → {'arp', 'ping', 'ports', ...}
            scan_stats = []        # lista de resúmenes por escaneo

            for s in scans:
                sid      = s['id']

                # Duración
                dur = ''
                try:
                    if s['started_at'] and s['completed_at']:
                        st = _dt.fromisoformat(str(s['started_at'])[:19])
                        en = _dt.fromisoformat(str(s['completed_at'])[:19])
                        dur = f"{max(0, int((en - st).total_seconds() / 60))} min"
                except Exception:
                    pass

                h_rows = conn.execute(
                    """SELECT h.ip_address, h.hostname,
                              h.mac_address, h.vendor,
                              sr.discovery_method, sr.port
                         FROM scan_results sr
                         JOIN hosts h ON h.id = sr.host_id
                        WHERE sr.scan_id = ?""",
                    (sid,)
                ).fetchall()
                seen_ips = set()
                for h in h_rows:
                    ip = h['ip_address']
                    seen_ips.add(ip)
                    if ip not in all_hosts or (h['mac_address'] and
                            not all_hosts[ip]['mac_address']):
                        all_hosts[ip] = {
                            'hostname':    h['hostname'],
                            'mac_address': h['mac_address'],
                            'vendor':      h['vendor'],
                        }
                    tech = self._method_to_technique(
                        h['discovery_method'], bool(h['mac_address']),
                        has_port=h['port'] is not None,
                    )
                    if tech:
                        host_techniques.setdefault(ip, set()).add(tech)
                h_count = len(seen_ips)
                p_count = 0
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
                    'mode':    'Activo',
                    'hosts':   h_count,
                    'ports':   p_count,
                    'dur':     dur,
                })
        finally:
            conn.close()

        # Clasificar hosts en redes conocidas / desconocidas
        net_count: Dict = {}
        unknown:   Dict = {}
        net_methods: Dict[str, set] = {}   # range → set of techniques
        for ip_str, hdata in sorted(all_hosts.items()):
            try:
                host_ip = _ipa.ip_address(ip_str)
            except ValueError:
                continue
            techs = host_techniques.get(ip_str, set())
            matched = False
            for n in known_nets:
                if host_ip in n['obj']:
                    net_count.setdefault(n['range'], {
                        'name': n['name'], 'system': n['system'],
                        'purdue': n['purdue'],
                        'hosts': [], 'known': True,
                    })['hosts'].append(ip_str)
                    net_methods.setdefault(n['range'], set()).update(techs)
                    matched = True
                    break
            if not matched:
                parts = ip_str.rsplit('.', 1)
                subnet = f"{parts[0]}.0/24" if len(parts) == 2 else '0.0.0.0/0'
                unknown.setdefault(subnet, []).append(ip_str)
                net_methods.setdefault(subnet, set()).update(techs)

        total_hosts   = len(all_hosts)
        total_ports   = sum(len(v) for v in port_map.values())
        first_date    = scan_stats[0]['date'] if scan_stats else '—'
        last_date     = scan_stats[-1]['date'] if scan_stats else '—'
        period        = first_date if first_date == last_date else f"{first_date} → {last_date}"

        ip_display = ip_filter if ip_filter else 'sin IP'
        lines = [
            VISIBILIDAD_START,
            '#### 🔍 Visibilidad de Redes — ArsenalOT',
            '',
            (f"**Vector de Acceso:** `{location}` · **IP de origen:** `{ip_display}`"
             f" · **Organización:** {org_name}  "),
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
            [{'range': r, 'name': '—', 'system': '—', 'purdue': '—', 'hosts': ips, 'known': False}
             for r, ips in unknown.items()]
        )
        if all_nets:
            all_nets.sort(key=lambda x: (not x['known'], x['range']))
            lines += [
                '##### Redes con Visibilidad',
                '',
                ('> _Visibilidad por capa — **ARP (L2)**: descubrimiento por capa 2'
                 ' (mismo segmento broadcast); **Ping (L3)** / **Ports (L3)**:'
                 ' visibilidad por capa 3 (enrutada); **Web (L7)**: evidencias web;'
                 ' **IOXID (L7)**: enumeración DCOM._'),
                '',
                '| Red | Nombre | Sistema | Purdue | Tipo | Visibilidad | Hosts únicos |',
                '|:---|:---|:---|:---:|:---|:---|---:|',
            ]
            for n in all_nets:
                tipo = '✅ Conocida' if n['known'] else '⚠️ Desconocida'
                vis = self._format_techniques(net_methods.get(n['range'], set()))
                lines.append(
                    f"| `{n['range']}` | {n['name']} | {n['system']}"
                    f" | {n['purdue']} | {tipo} | {vis} | {len(n['hosts'])} |"
                )
            lines.append('')

        critical_access = []
        for dev in critical_rows:
            for ip_text in str(dev['ips'] or '').split(','):
                ip_text = ip_text.strip()
                if not ip_text or ip_text not in all_hosts:
                    continue
                ports = sorted(
                    port_map.get(ip_text, set()),
                    key=lambda p: int(p.split('/')[0]) if p.split('/')[0].isdigit() else 0,
                )
                critical_access.append({
                    'name': dev['name'] or '—',
                    'ip': ip_text,
                    'system': dev['system_name'] or '—',
                    'reason': dev['reason'] or '—',
                    'services': ', '.join(ports[:8]) or '—',
                })

        if critical_access:
            lines += [
                '##### Activos Críticos Accesibles desde este Origen',
                '',
                '| Activo | IP | Sistema | Motivo | Servicios detectados |',
                '|:---|:---|:---|:---|:---|',
            ]
            for dev in critical_access:
                lines.append(
                    f"| {dev['name']} | `{dev['ip']}` | {dev['system']}"
                    f" | {dev['reason']} | {dev['services']} |"
                )
            lines.append('')

        # Tabla de hosts
        if all_hosts:
            lines += [
                '##### Hosts Descubiertos',
                '',
                '| IP | Hostname | MAC / Vendor | Visibilidad | Servicios detectados |',
                '|:---|:---|:---|:---|:---|',
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
                vis_str = self._format_techniques(host_techniques.get(ip_str, set()))
                lines.append(
                    f"| `{ip_str}` | `{hn}` | {mac_str} | {vis_str} | {svc_str} |"
                )
            lines.append('')

        lines.append(VISIBILIDAD_END)
        return '\n'.join(lines)

    def update_location_visibility(self, org_name: str, location: str,
                                    db_path,
                                    myip: Optional[str] = None) -> bool:
        """
        Actualiza el bloque ARSENAL:VISIBILIDAD de la nota del vector de acceso
        para el par (location, myip). Solo reemplaza ese bloque; el resto del
        documento queda intacto.
        """
        note_path = self._find_location_note_path(org_name, location, myip)
        if note_path is None:
            return False
        self.update_location_metadata(org_name, location, db_path, myip)
        block = self._build_location_visibility_block(org_name, location,
                                                       db_path, myip)
        if not block:
            return False
        content     = note_path.read_text(encoding='utf-8')
        new_content = self._inject_or_replace_visibility(content, block)
        if new_content != content:
            note_path.write_text(new_content, encoding='utf-8')
            _open_permissions(note_path)
        self.update_location_visibility_diagram(org_name, location, db_path, myip)
        return True

    # ─────────────────────────────────────────────────────────
    # Creación automática desde vectores de acceso (location)
    # ─────────────────────────────────────────────────────────

    def _migrate_legacy_note(self, org_name: str, location: str,
                              myip: Optional[str]) -> Optional[Path]:
        """
        Si existe la nota legacy `*VE - LOCATION.md` (sin sufijo de IP) y aún
        no existe la nota correspondiente al par (location, myip), renombra
        la legacy añadiendo el sufijo (IP) preservando contenido manual.

        Devuelve la ruta nueva si renombró algo, None en caso contrario.
        El llamador debe asegurarse de que sólo hay una IP candidata para esta
        location antes de invocar (de lo contrario puede mezclar contenido).
        """
        legacy = self._find_legacy_location_note_path(org_name, location)
        if legacy is None:
            return None

        bitacoras = legacy.parent
        # Reemplazar el sufijo del nombre conservando la fecha original.
        new_name = legacy.stem + f" ({self._ip_label(myip)}).md"
        new_path = bitacoras / new_name
        if new_path.exists():
            return None  # destino ya existe; no tocar

        try:
            legacy.rename(new_path)
            _open_permissions(new_path)
            return new_path
        except OSError:
            return None

    def create_location_note(self, org_name: str, location: str,
                              first_date: str,
                              myip: Optional[str] = None) -> bool:
        """
        Crea la nota de bitácora para un vector de acceso (location, myip).
        Nombre: ``YYYY-MM-DD - VE - {LOCATION} ({IP}).md`` (o ``(sin IP)`` si
        no se conoce). Devuelve True si la creó, False si ya existía.

        Nota: la migración de notas legacy (sin sufijo IP) la decide el
        llamador llamando a :meth:`_migrate_legacy_note` antes; aquí no se
        renombra automáticamente porque, si hay varias IPs para esa
        location, no se puede saber a cuál pertenece el contenido manual.
        """
        # ── Comprobar si ya existe la nota concreta para (location, myip) ──
        if self._find_location_note_path(org_name, location, myip) is not None:
            return False

        file_title = f"{first_date} - {self._note_basename(location, myip)}"
        rel_path   = f"PENTEST IT OT/Bitacoras/{file_title}.md"

        org_dir = self.get_org_dir(org_name)
        # Comprobación exacta por si _find_location_note_path no la localizó
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
        cliente_label = (f"{location} ({self._ip_label(myip)})"
                         if (myip or '').strip() else location)
        content = content.replace(
            '| **Cliente / Objetivo** | `...` |',
            f'| **Cliente / Objetivo** | `{cliente_label}` |',
        )

        self.create_file(org_name, rel_path, content)
        return True

    # ─────────────────────────────────────────────────────────
    # Evidencias web (screenshots + source code)
    # ─────────────────────────────────────────────────────────

    def _evidencias_dir(self, org_name: str) -> Path:
        """Carpeta destino para evidencias de esta org dentro de la bitácora."""
        d = (self.get_org_dir(org_name)
             / "PENTEST IT OT" / "Bitacoras" / EVIDENCIAS_SUBDIR)
        d.mkdir(parents=True, exist_ok=True)
        _open_permissions(d)
        src_d = d / "source"
        src_d.mkdir(parents=True, exist_ok=True)
        _open_permissions(src_d)
        return d

    def _fetch_evidencias(self, org_name: str, location: str,
                          db_path,
                          myip: Optional[str] = None) -> Dict[str, list]:
        """
        Consulta la BD y devuelve las evidencias de los escaneos de una
        location. Si se proporciona ``myip``, filtra por esa IP de origen
        (o por escaneos sin IP cuando ``myip`` es None/'').

        Retorna:
          {
            'screenshots': [{'ip', 'port', 'file_path'}, ...],
            'sources':     [{'ip', 'port', 'file_path'}, ...],
          }
        """
        ip_filter = (myip or '').strip() or None

        conn = sqlite3.connect(str(db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        screenshots = []
        sources = []
        try:
            scan_q = """SELECT id FROM scans
                       WHERE UPPER(organization_name) = UPPER(?)
                         AND UPPER(location) = UPPER(?)
                         AND status = 'completed'"""
            scan_params = [org_name, location]
            if ip_filter is not None:
                scan_q += " AND myip = ?"
                scan_params.append(ip_filter)
            else:
                scan_q += " AND (myip IS NULL OR myip = '')"
            scan_ids = [r['id'] for r in conn.execute(scan_q, scan_params).fetchall()]

            if not scan_ids:
                return {'screenshots': [], 'sources': []}

            placeholders = ','.join('?' * len(scan_ids))
            rows = conn.execute(
                f"""SELECT LOWER(e.enrichment_type) AS etype, e.file_path,
                           sr.scan_id,
                           h.ip_address, sr.port
                    FROM enrichments e
                    JOIN scan_results sr ON sr.id = e.scan_result_id
                    JOIN hosts h ON h.id = sr.host_id
                    WHERE sr.scan_id IN ({placeholders})
                      AND LOWER(e.enrichment_type) IN ('screenshot', 'websource',
                                                        'source_code', 'source')
                      AND e.file_path IS NOT NULL
                    ORDER BY h.ip_address, sr.port, sr.scan_id DESC""",
                scan_ids
            ).fetchall()

            seen_ss  = set()
            seen_src = set()
            for r in rows:
                key   = (r['ip_address'], r['port'])
                entry = {'ip': r['ip_address'], 'port': r['port'],
                         'scan_id': r['scan_id'],
                         'file_path': r['file_path']}
                etype = r['etype']
                if etype == 'screenshot' and key not in seen_ss:
                    screenshots.append(entry)
                    seen_ss.add(key)
                elif etype in ('websource', 'source_code', 'source') and key not in seen_src:
                    sources.append(entry)
                    seen_src.add(key)
        finally:
            conn.close()

        return {'screenshots': screenshots, 'sources': sources}

    def _resolve_evidence_path(self, file_path: str) -> Path:
        """
        Resuelve la ruta de evidencia almacenada en BD.
        Los paths en BD son relativos al directorio padre de results_root
        (p. ej. 'results/ORG/scan_xxx/img/x.png') o absolutos.
        """
        p = Path(file_path)
        if p.is_absolute():
            return p
        # Intentar relativo al padre de results_root (raíz del proyecto)
        candidate = self.results_root.parent / p
        if candidate.exists():
            return candidate
        # Intentar relativo a results_root directamente (por si acaso)
        candidate2 = self.results_root / p
        if candidate2.exists():
            return candidate2
        # Devolver el primero aunque no exista (el caller comprobará .exists())
        return candidate

    def _copy_evidencias(self, org_name: str, evidencias: Dict[str, list]) -> Dict[str, list]:
        """
        Copia los archivos de evidencia al vault de Obsidian.
        Devuelve los mismos dicts con 'vault_name' añadido (nombre de archivo en vault).
        """
        ev_dir  = self._evidencias_dir(org_name)
        src_dir = ev_dir / "source"

        for ev in evidencias['screenshots']:
            src = self._resolve_evidence_path(ev['file_path'])
            if not src.exists():
                ev['vault_name'] = None
                continue
            name = f"scan_{ev.get('scan_id')}_{ev['ip']}_{ev['port']}.png"
            dst  = ev_dir / name
            try:
                shutil.copy2(src, dst)
                _open_permissions(dst)
                ev['vault_name'] = name
            except Exception:
                ev['vault_name'] = None

        for ev in evidencias['sources']:
            src = self._resolve_evidence_path(ev['file_path'])
            if not src.exists():
                ev['vault_name'] = None
                continue
            name = f"scan_{ev.get('scan_id')}_{ev['ip']}_{ev['port']}.txt"
            dst  = src_dir / name
            try:
                shutil.copy2(src, dst)
                _open_permissions(dst)
                ev['vault_name'] = f"source/{name}"
            except Exception:
                ev['vault_name'] = None

        return evidencias

    def _build_evidencias_block(self, evidencias: Dict[str, list]) -> str:
        """Construye el bloque Markdown de evidencias para insertar en la nota."""
        shots  = [e for e in evidencias['screenshots'] if e.get('vault_name')]
        srcs   = [e for e in evidencias['sources']     if e.get('vault_name')]

        if not shots and not srcs:
            return ''

        lines = [EVIDENCIAS_START, '#### 📸 Evidencias Web — ArsenalOT', '']

        if shots:
            lines += [
                '##### Capturas de Pantalla',
                '',
                '| Host | Puerto | Captura |',
                '|:---|:---|:---|',
            ]
            for e in shots:
                # Obsidian resuelve wiki-links por nombre de archivo
                lines.append(
                    f"| `{e['ip']}` | {e['port']} | ![[{e['vault_name']}]] |"
                )
            lines.append('')

        if srcs:
            lines += ['##### Código Fuente', '']
            for e in srcs:
                lines.append(
                    f"- [[{e['vault_name']}|{e['ip']}:{e['port']} — código fuente]]"
                )
            lines.append('')

        lines.append(EVIDENCIAS_END)
        return '\n'.join(lines)

    def _inject_or_replace_evidencias(self, content: str, block: str) -> str:
        """Reemplaza el bloque existente o lo añade al final del documento."""
        if EVIDENCIAS_START in content and EVIDENCIAS_END in content:
            s = content.index(EVIDENCIAS_START)
            e = content.index(EVIDENCIAS_END) + len(EVIDENCIAS_END)
            return content[:s] + block + content[e:]
        return content.rstrip() + f'\n\n{block}\n'

    def update_location_evidence(self, org_name: str, location: str,
                                  db_path,
                                  myip: Optional[str] = None) -> bool:
        """
        Copia las evidencias de los escaneos de (location, myip) al vault y
        actualiza el bloque ARSENAL:EVIDENCIAS de su nota. Devuelve True si
        actualizó algo.
        """
        note_path = self._find_location_note_path(org_name, location, myip)
        if note_path is None:
            return False

        evidencias = self._fetch_evidencias(org_name, location, db_path, myip)
        if not evidencias['screenshots'] and not evidencias['sources']:
            return False

        evidencias = self._copy_evidencias(org_name, evidencias)
        block = self._build_evidencias_block(evidencias)
        if not block:
            return False

        content     = note_path.read_text(encoding='utf-8')
        new_content = self._inject_or_replace_evidencias(content, block)
        if new_content != content:
            note_path.write_text(new_content, encoding='utf-8')
            _open_permissions(note_path)
        return True

    def _remove_duplicate_notes(self, org_name: str, location: str,
                                 myip: Optional[str] = None):
        """
        Si existen varias notas para el par (location, myip), conserva la más
        antigua (primera alfabéticamente) y elimina las demás, pero solo si el
        contenido de la duplicada es exclusivamente bloques auto-gestionados
        por ArsenalOT (no hay edición manual). Las duplicadas con contenido
        manual se dejan intactas para que el usuario las revise.

        Si ``myip`` es None, opera sobre las notas legacy (sin sufijo de IP).
        """
        bitacoras = self.get_org_dir(org_name) / "PENTEST IT OT" / "Bitacoras"
        if not bitacoras.exists():
            return
        if myip is None:
            hits = sorted(bitacoras.glob(f"*VE - {location}.md"))
        else:
            label = self._ip_label(myip)
            hits = sorted(bitacoras.glob(f"*VE - {location} ({label}).md"))
        if len(hits) <= 1:
            return   # Sin duplicados

        canonical = hits[0]   # La más antigua — la que conservamos
        for dup in hits[1:]:
            try:
                text = dup.read_text(encoding='utf-8', errors='replace')
                # Considerar "sin edición manual" si solo contiene bloques ARSENAL
                # o el texto de la plantilla sin rellenar (líneas vacías, encabezados
                # de plantilla, marcadores ARSENAL).
                # Heurística: si NO hay nada fuera de los bloques gestionados y
                # las primeras líneas de plantilla, es seguro eliminar.
                stripped = text
                for marker_pair in [
                    (VISIBILIDAD_START, VISIBILIDAD_END),
                    (EVIDENCIAS_START,  EVIDENCIAS_END),
                    (self.FINDINGS_START, self.FINDINGS_END),
                ]:
                    if marker_pair[0] in stripped and marker_pair[1] in stripped:
                        s = stripped.index(marker_pair[0])
                        e = stripped.index(marker_pair[1]) + len(marker_pair[1])
                        stripped = stripped[:s] + stripped[e:]

                # Descontar líneas que son boilerplate de plantilla:
                # encabezados, separadores, placeholders `...`, referencias
                # de plantilla, comentarios HTML, líneas vacías, etc.
                manual_lines = [
                    ln for ln in stripped.strip().splitlines()
                    if ln.strip()
                    and not ln.startswith('#')
                    and not ln.startswith('|')
                    and not ln.startswith('>')
                    and not ln.startswith('---')
                    and not ln.startswith('***')
                    and not ln.startswith('<!--')
                    and 'tp.file'      not in ln
                    and 'YYYY-MM-DD'   not in ln
                    and '`...`'        not in ln   # placeholder sin rellenar
                    and ln.strip() not in ('...', '`...`', '-', '*')
                ]
                # Si el contenido real (sin plantilla) es mínimo, es seguro borrar
                if len('\n'.join(manual_lines)) < 300:
                    dup.unlink()
            except Exception:
                pass   # Nunca bloquear por error en limpieza

    def fill_from_scans(self, org_name: str, db_path) -> dict:
        """
        Crea/actualiza una nota por cada par (vector de acceso, IP de origen)
        con escaneos completados. No sobreescribe contenido manual fuera del
        bloque de visibilidad.

        Cuando para una location existe nota legacy (sin sufijo de IP) y solo
        se ha registrado una IP única para esa location, la nota legacy se
        renombra preservando el contenido. Si hay varias IPs, la legacy se
        deja intacta para que el usuario decida.

        Devuelve {created, skipped, evidence_copied, errors, renamed}.
        """
        created         = 0
        skipped         = 0
        evidence_copied = 0
        renamed         = 0
        errors          = []

        conn = sqlite3.connect(str(db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            # Una nota por (location, myip). Tratamos NULL y '' como "sin IP".
            pair_rows = conn.execute(
                """SELECT location,
                          CASE WHEN myip IS NULL OR myip = '' THEN NULL ELSE myip END AS myip,
                          MIN(started_at) AS first_scan
                   FROM scans
                   WHERE UPPER(organization_name) = UPPER(?) AND status = 'completed'
                   GROUP BY location, CASE WHEN myip IS NULL OR myip = '' THEN NULL ELSE myip END
                   ORDER BY location, myip""",
                (org_name,)
            ).fetchall()
        finally:
            conn.close()

        # Cuántas IPs distintas tiene cada location (incluye 'sin IP')
        ip_count_by_loc: Dict[str, int] = {}
        for r in pair_rows:
            ip_count_by_loc[r['location']] = ip_count_by_loc.get(r['location'], 0) + 1

        for lr in pair_rows:
            location   = lr['location']
            myip       = lr['myip']  # None si era NULL o ''
            first_date = str(lr['first_scan'] or '')[:10]
            try:
                # Migrar nota legacy SOLO si hay una única IP para esta location
                # (de lo contrario no podemos saber a qué IP pertenece su contenido).
                if ip_count_by_loc[location] == 1:
                    if self._migrate_legacy_note(org_name, location, myip) is not None:
                        renamed += 1

                # Eliminar duplicados auto-generados para este par concreto.
                self._remove_duplicate_notes(org_name, location, myip)

                was_created = self.create_location_note(org_name, location,
                                                         first_date, myip)
                if was_created:
                    created += 1
                else:
                    skipped += 1
                self.update_location_visibility(org_name, location, db_path, myip)
                # Copiar evidencias y actualizar bloque
                evidencias = self._fetch_evidencias(org_name, location, db_path, myip)
                total_ev   = (len(evidencias['screenshots'])
                              + len(evidencias['sources']))
                if total_ev > 0 and self.update_location_evidence(org_name, location, db_path, myip):
                    evidence_copied += total_ev
            except Exception as e:
                tag = f"{location} ({self._ip_label(myip)})"
                errors.append(f"{tag}: {str(e)}")

        return {
            'created':         created,
            'skipped':         skipped,
            'renamed':         renamed,
            'evidence_copied': evidence_copied,
            'errors':          errors,
        }

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

    # ─────────────────────────────────────────────────────────
    # Credenciales — bloque gestionado en CREDENCIALES.md
    # ─────────────────────────────────────────────────────────

    CREDS_START = '<!-- ARSENAL:CREDENCIALES-NETEXEC -->'
    CREDS_END   = '<!-- /ARSENAL:CREDENCIALES-NETEXEC -->'

    # Protocolos OT vs IT — todo lo que NetExec descubre es IT, pero permitimos
    # que el caller indique IT/OT vía el dict de credencial (campo opcional).
    _IT_PROTOCOLS = {'smb', 'ssh', 'ldap', 'mssql', 'winrm', 'rdp', 'ftp',
                     'wmi', 'vnc', 'nfs'}

    def _get_creds_note_path(self, org_name: str) -> Path:
        """Ruta de CREDENCIALES.md dentro de la org (la crea si no existe)."""
        org_dir   = self.get_org_dir(org_name)
        note_path = org_dir / "PENTEST IT OT" / "Bitacoras" / "NOTAS" / "CREDENCIALES.md"
        note_path.parent.mkdir(parents=True, exist_ok=True)
        _open_permissions(note_path.parent)
        if not note_path.exists():
            note_path.write_text("## IT\n\n## OT\n", encoding="utf-8")
            _open_permissions(note_path)
        return note_path

    @staticmethod
    def _md_escape(value) -> str:
        if value is None:
            return ''
        s = str(value)
        return s.replace('|', '\\|').replace('\n', ' ').strip()

    @staticmethod
    def _mask_password(value: Optional[str], credtype: Optional[str]) -> str:
        """Devuelve la password/hash tal cual si es hash, o `***` si es plaintext.

        La bitácora vive en el vault del usuario y es visible; preferimos no
        exponer plaintext directamente. El usuario siempre puede consultar la
        password cruda en `arsenal.db` (tabla credentials) si lo necesita.
        """
        if not value:
            return ''
        if (credtype or '').lower() == 'hash':
            # Hashes (NTLM, etc.) son útiles tal cual para PtH
            return value
        # plaintext: mostrar parcial — primeros 2 chars + ***
        if len(value) <= 2:
            return '***'
        return f"{value[:2]}{'*' * (len(value) - 2)}"

    def add_credentials_to_note(
        self,
        org_name: str,
        credentials: List[Dict],
        scan_id: Optional[int] = None,
    ) -> Dict:
        """
        Renderiza un bloque ARSENAL:CREDENCIALES-NETEXEC en CREDENCIALES.md
        bajo la sección ## IT, con una tabla por dominio.

        Idempotente: si el bloque ya existe lo reemplaza completamente con la
        nueva lista (para mantener una vista cumulativa pasa el resultado de
        ``storage.get_credentials(org_name)``).

        ``credentials`` es lista de dicts con claves:
            domain, username, password, credtype, source_protocol, source_host_ip
        """
        from datetime import datetime as _dt

        note_path = self._get_creds_note_path(org_name)
        content   = note_path.read_text(encoding="utf-8")

        # Deduplicar por (domain, username, password, credtype)
        seen = set()
        deduped = []
        for c in credentials or []:
            key = (
                (c.get('domain') or '').lower(),
                (c.get('username') or '').lower(),
                c.get('password') or '',
                (c.get('credtype') or '').lower(),
            )
            if not c.get('username') or key in seen:
                continue
            seen.add(key)
            deduped.append(c)

        # Agrupar por dominio (vacío → "WORKGROUP")
        by_domain: Dict[str, List[Dict]] = {}
        for c in deduped:
            dom = (c.get('domain') or 'WORKGROUP').strip() or 'WORKGROUP'
            by_domain.setdefault(dom, []).append(c)

        ts = _dt.now().strftime("%Y-%m-%d %H:%M")
        scan_tag = f" (scan #{scan_id})" if scan_id else ""

        # Construir cuerpo del bloque
        if not deduped:
            block_body = (
                f"\n### Credenciales NetExec{scan_tag}\n\n"
                f"_Sin credenciales — última actualización {ts}._\n\n"
            )
        else:
            lines = [f"\n### Credenciales NetExec{scan_tag}\n"]
            lines.append(f"_Total: {len(deduped)} credenciales · "
                         f"última actualización {ts}_\n")
            for dom in sorted(by_domain.keys(), key=str.lower):
                rows = sorted(
                    by_domain[dom],
                    key=lambda x: ((x.get('username') or '').lower(),
                                   x.get('source_host_ip') or '')
                )
                lines.append(f"\n#### Dominio: `{self._md_escape(dom)}`\n")
                lines.append(
                    "| Usuario | Password / Hash | Tipo | Protocolo | Host origen |"
                )
                lines.append(
                    "|---------|-----------------|------|-----------|-------------|"
                )
                for r in rows:
                    masked = self._mask_password(
                        r.get('password'), r.get('credtype')
                    )
                    lines.append("| {u} | `{p}` | {t} | {pr} | {h} |".format(
                        u=self._md_escape(r.get('username')),
                        p=self._md_escape(masked) or '—',
                        t=self._md_escape(r.get('credtype')) or 'plaintext',
                        pr=self._md_escape(r.get('source_protocol')) or '—',
                        h=self._md_escape(r.get('source_host_ip')) or '—',
                    ))
                lines.append("")
            block_body = "\n".join(lines) + "\n"

        new_block = (
            "\n"
            + self.CREDS_START + "\n"
            + block_body
            + self.CREDS_END + "\n"
        )

        # Reemplazar bloque existente o insertarlo bajo "## IT"
        if self.CREDS_START in content and self.CREDS_END in content:
            pre, rest      = content.split(self.CREDS_START, 1)
            _, post        = rest.split(self.CREDS_END, 1)
            # Quitar el "\n" inicial que añadiremos al recomponer
            pre = pre.rstrip("\n") + "\n"
            new_content = pre + self.CREDS_START + "\n" + block_body + self.CREDS_END + post
        elif "## IT" in content:
            # Insertar justo después del encabezado ## IT (antes de ## OT si existe)
            head, tail = content.split("## IT", 1)
            # tail empieza tras "## IT"; preservamos el resto y metemos el bloque al inicio
            new_content = head + "## IT\n" + new_block + tail.lstrip("\n")
        else:
            # Sin sección IT — anexar al final
            new_content = content.rstrip("\n") + "\n\n## IT\n" + new_block

        note_path.write_text(new_content, encoding="utf-8")
        _open_permissions(note_path)

        return {
            'note': str(note_path),
            'credentials_written': len(deduped),
            'domains': sorted(by_domain.keys()),
        }

    def clear_credentials_note(self, org_name: str) -> Dict:
        """Remove the managed NetExec credentials block from CREDENCIALES.md."""
        note_path = self._get_creds_note_path(org_name)
        content = note_path.read_text(encoding="utf-8")
        removed = False
        if self.CREDS_START in content and self.CREDS_END in content:
            pre, rest = content.split(self.CREDS_START, 1)
            _, post = rest.split(self.CREDS_END, 1)
            content = pre.rstrip("\n") + "\n" + post.lstrip("\n")
            removed = True
        note_path.write_text(content, encoding="utf-8")
        _open_permissions(note_path)
        return {'note': str(note_path), 'removed': removed}
