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


def _safe_path(base: Path, user_path: str) -> Path:
    """Resuelve un path relativo y verifica que no salga del base (path traversal)."""
    resolved = (base / user_path.lstrip("/")).resolve()
    if not str(resolved).startswith(str(base.resolve())):
        raise PermissionError(f"Path traversal bloqueado: {user_path!r}")
    return resolved


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
        self.orgs_root.mkdir(parents=True, exist_ok=True)

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

        if not TEMPLATE_DIR.exists():
            # Crear estructura mínima si no hay template
            (org_dir / "PENTEST IT OT" / "Bitacoras").mkdir(parents=True, exist_ok=True)
            (org_dir / "PENTEST IT OT" / "Plantillas").mkdir(parents=True, exist_ok=True)
            (org_dir / "EV. DISPOSITIVOS" / "62443" / "Bitacoras").mkdir(parents=True, exist_ok=True)
            return org_dir

        for subdir_name in ORG_TEMPLATE_SUBDIRS:
            src = TEMPLATE_DIR / subdir_name
            dst = org_dir / subdir_name
            if src.exists() and not dst.exists():
                shutil.copytree(src, dst)

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
        fpath.write_text(content, encoding="utf-8")
        new_mtime = fpath.stat().st_mtime
        return True, None, new_mtime

    def create_file(self, org_name: str, rel_path: str, initial_content: str = "") -> float:
        """Crea un archivo nuevo (error si ya existe)."""
        org_dir = self.get_org_dir(org_name)
        fpath = _safe_path(org_dir, rel_path)
        if fpath.exists():
            raise FileExistsError(f"El archivo ya existe: {rel_path}")
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(initial_content, encoding="utf-8")
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
    # Creación automática desde escaneos ORIGEN
    # ─────────────────────────────────────────────────────────

    def create_origen_note(self, org_name: str, scan_id: int, scan_mode: str,
                            target_range: str, started_at) -> bool:
        """
        Crea una nota de bitácora desde la plantilla CHECKLIST-PENTEST para un escaneo.
        Nombre del archivo: YYYY-MM-DD - VE - Escaneo {id}.md  (o ESCANEO PASIVO {id})
        Devuelve True si la creó, False si ya existía.
        """
        from datetime import datetime as _dt

        mode = (scan_mode or 'active').lower()
        if mode == 'passive':
            origin_name = f"ESCANEO PASIVO {scan_id}"
        else:
            origin_name = f"Escaneo {scan_id}"

        # Fecha del escaneo
        if started_at:
            if isinstance(started_at, str):
                date_str = started_at[:10]  # YYYY-MM-DD
            elif hasattr(started_at, 'strftime'):
                date_str = started_at.strftime('%Y-%m-%d')
            else:
                date_str = _dt.now().strftime('%Y-%m-%d')
        else:
            date_str = _dt.now().strftime('%Y-%m-%d')

        file_title = f"{date_str} - VE - {origin_name}"
        rel_path = f"PENTEST IT OT/Bitacoras/{file_title}.md"

        # Comprobar si ya existe (silencio)
        org_dir = self.get_org_dir(org_name)
        if (org_dir / rel_path).exists():
            return False

        # Leer plantilla (desde la copia de la org o desde el template fuente)
        template_path = org_dir / "PENTEST IT OT/Plantillas/CHECKLIST-PENTEST.md"
        if not template_path.exists():
            template_path = TEMPLATE_DIR / "PENTEST IT OT/Plantillas/CHECKLIST-PENTEST.md"

        if template_path.exists():
            content = template_path.read_text(encoding='utf-8')
        else:
            content = f"# {file_title}\n\n"

        # Sustituir variables de Templater por valores reales
        content = content.replace('<% tp.file.title %>', file_title)
        # Primera ocurrencia de la fecha en la tabla de metadatos
        content = content.replace('`YYYY-MM-DD`', f'`{date_str}`', 1)
        # Objetivo/target si es significativo
        _skip_targets = {'imported_from_xml', 'imported_pcap', '0.0.0.0/0', 'N/A', ''}
        if target_range and target_range not in _skip_targets:
            content = content.replace(
                '| **Cliente / Objetivo** | `...` |',
                f'| **Cliente / Objetivo** | `{target_range}` |',
            )

        self.create_file(org_name, rel_path, content)
        return True

    def fill_from_scans(self, org_name: str, db_path) -> dict:
        """
        Crea notas de bitácora para todos los escaneos completados sin nota existente.
        Devuelve {created, skipped, errors}.
        """
        import sqlite3 as _sqlite3

        created = 0
        skipped = 0
        errors = []

        conn = _sqlite3.connect(str(db_path), timeout=10.0)
        conn.row_factory = _sqlite3.Row
        try:
            rows = conn.execute(
                """SELECT id, scan_mode, target_range, started_at
                   FROM scans
                   WHERE UPPER(organization_name) = UPPER(?) AND status = 'completed'
                   ORDER BY id""",
                (org_name,)
            ).fetchall()
        finally:
            conn.close()

        for row in rows:
            try:
                was_created = self.create_origen_note(
                    org_name, row['id'], row['scan_mode'] or 'active',
                    row['target_range'], row['started_at']
                )
                if was_created:
                    created += 1
                else:
                    skipped += 1
            except Exception as e:
                errors.append(f"Scan {row['id']}: {str(e)}")

        return {'created': created, 'skipped': skipped, 'errors': errors}
