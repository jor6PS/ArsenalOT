"""
API routes para la bitácora Obsidian integrada.
"""

from pathlib import Path
from typing import Optional
import re

from fastapi import APIRouter, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from arsenal.web.core.deps import storage
from arsenal.core.bitacora_manager import BitacoraManager

router = APIRouter(prefix="/api/bitacora", tags=["bitacora"])


def _get_manager() -> BitacoraManager:
    return BitacoraManager(storage.results_root)


# ── Pydantic models ───────────────────────────────────────────

class WriteFileRequest(BaseModel):
    content: str
    client_mtime: Optional[float] = None   # ETag del cliente para detección de conflictos


class CreateFileRequest(BaseModel):
    path: str                               # relativo a org_dir
    content: str = ""
    is_folder: bool = False


class RenameRequest(BaseModel):
    old_path: str
    new_path: str


class NewVectorRequest(BaseModel):
    name: str


# ── Endpoints ────────────────────────────────────────────────

class CandidateEvidenceItem(BaseModel):
    label: str
    value: str


class CandidateBitacoraRequest(BaseModel):
    candidate_id: str
    title: str
    severity_label: Optional[str] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    summary: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    evidence: list[CandidateEvidenceItem] = []
    report_hint: Optional[str] = None


def _candidate_note_path(audit_type: str = "infra") -> str:
    root = BitacoraManager._bitacora_root_rel(audit_type)
    return f"{root}/NOTAS/CANDIDATOS.md"


def _candidate_marker(candidate_id: str) -> tuple[str, str]:
    safe_id = re.sub(r"[^A-Za-z0-9_.:-]", "-", candidate_id or "")
    return (
        f"<!-- ARSENAL:CANDIDATE:{safe_id} -->",
        f"<!-- /ARSENAL:CANDIDATE:{safe_id} -->",
    )


def _candidate_md_escape(value) -> str:
    return str(value or "").replace("\n", " ").strip()


def _candidate_to_markdown(candidate: CandidateBitacoraRequest) -> str:
    severity = _candidate_md_escape(candidate.severity_label or "Sin severidad")
    category = _candidate_md_escape(candidate.category or "Sin categoría")
    rule = _candidate_md_escape(candidate.rule_name or candidate.rule_id or "Sin regla")
    lines = [
        f"## {candidate.title}",
        "",
        f"- **Severidad:** {severity}",
        f"- **Categoría:** {category}",
        f"- **Regla:** {rule}",
        f"- **ID candidato:** `{_candidate_md_escape(candidate.candidate_id)}`",
        "",
    ]
    if candidate.summary:
        lines += ["### Resumen", "", candidate.summary.strip(), ""]
    if candidate.evidence:
        lines += ["### Evidencia", ""]
        for item in candidate.evidence:
            if item.label and item.value:
                lines.append(f"- **{_candidate_md_escape(item.label)}:** {_candidate_md_escape(item.value)}")
        lines.append("")
    if candidate.impact:
        lines += ["### Impacto potencial", "", candidate.impact.strip(), ""]
    if candidate.recommendation:
        lines += ["### Recomendación", "", candidate.recommendation.strip(), ""]
    lines += ["> Candidato pendiente de validación por el auditor. No equivale automáticamente a un finding final.", ""]
    return "\n".join(lines)


@router.get("/{org_name}/info")
async def get_bitacora_info(org_name: str):
    """Devuelve la ruta del vault y si la org tiene bitácora inicializada."""
    mgr = _get_manager()
    org_dir = mgr.get_org_dir(org_name)
    return {
        "vault_path": mgr.get_vault_path(),
        "org_path": str(org_dir.resolve()),
        "initialized": org_dir.exists(),
    }


@router.get("/{org_name}/tree")
async def get_tree(org_name: str):
    """Árbol de archivos de la bitácora de una org."""
    try:
        mgr = _get_manager()
        tree = await run_in_threadpool(mgr.get_file_tree, org_name)
        return {"tree": tree}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{org_name}/manifest")
async def get_bitacora_manifest(
    org_name: str,
    audit_type: str = Query("infra", description="infra o device"),
):
    """Vista filtrada de bitacora editable para una organizacion."""
    try:
        mgr = _get_manager()
        return await run_in_threadpool(mgr.get_bitacora_manifest, org_name, audit_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/guides/catalog/tree")
async def get_guides_tree():
    """Arbol de guias del template maestro, en solo lectura."""
    try:
        mgr = _get_manager()
        tree = await run_in_threadpool(mgr.get_guides_tree)
        return {"tree": tree}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/guides/catalog/file")
async def read_guide_file(path: str = Query(..., description="Ruta relativa de la guia")):
    """Lee una guia del template maestro."""
    try:
        mgr = _get_manager()
        content, mtime = await run_in_threadpool(mgr.read_guide_file, path)
        return {"content": content, "mtime": mtime, "path": path}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{org_name}/candidate-findings")
async def get_candidate_findings_in_bitacora(
    org_name: str,
    audit_type: str = Query("infra", description="infra o device"),
):
    """Lista los candidatos ya incluidos en la nota CANDIDATOS.md."""
    try:
        mgr = _get_manager()
        await run_in_threadpool(mgr.get_bitacora_manifest, org_name, audit_type)
        note_path = _candidate_note_path(audit_type)
        content, mtime = await run_in_threadpool(mgr.read_file, org_name, note_path)
        ids = re.findall(r"<!-- ARSENAL:CANDIDATE:([^>]+) -->", content)
        return {"candidate_ids": ids, "path": note_path, "mtime": mtime}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_name}/candidate-findings")
async def add_candidate_finding_to_bitacora(
    org_name: str,
    body: CandidateBitacoraRequest,
    audit_type: str = Query("infra", description="infra o device"),
):
    """Incluye un candidato en CANDIDATOS.md de forma idempotente."""
    try:
        if not body.candidate_id or not body.title:
            raise HTTPException(status_code=400, detail="candidate_id y title son obligatorios")

        mgr = _get_manager()
        await run_in_threadpool(mgr.get_bitacora_manifest, org_name, audit_type)
        note_path = _candidate_note_path(audit_type)
        content, mtime = await run_in_threadpool(mgr.read_file, org_name, note_path)
        start_marker, end_marker = _candidate_marker(body.candidate_id)

        if start_marker in content:
            return {
                "ok": True,
                "already_exists": True,
                "message": "El candidato ya está incluido en la bitácora.",
                "path": note_path,
                "mtime": mtime,
            }

        block = "\n".join([
            start_marker,
            _candidate_to_markdown(body).strip(),
            end_marker,
            "",
        ])
        new_content = content.rstrip() + "\n\n" + block
        _, _, new_mtime = await run_in_threadpool(mgr.write_file, org_name, note_path, new_content, None)
        return {
            "ok": True,
            "already_exists": False,
            "message": "Candidato incluido en la bitácora.",
            "path": note_path,
            "mtime": new_mtime,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{org_name}/file")
async def read_file(org_name: str, path: str = Query(..., description="Ruta relativa al dir de la org")):
    """Lee un archivo de la bitácora."""
    try:
        mgr = _get_manager()
        content, mtime = await run_in_threadpool(mgr.read_file, org_name, path)
        return {"content": content, "mtime": mtime, "path": path}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{org_name}/file")
async def write_file(
    org_name: str,
    path: str = Query(...),
    body: WriteFileRequest = ...,
):
    """
    Guarda un archivo. Detecta conflictos si se envía client_mtime.

    Respuesta en conflicto (409):
      { conflict: true, disk_content: "...", disk_mtime: 1234.5 }
    Respuesta OK (200):
      { ok: true, mtime: 1234.5 }
    """
    try:
        mgr = _get_manager()
        ok, disk_content, new_mtime = await run_in_threadpool(
            mgr.write_file,
            org_name, path, body.content, body.client_mtime
        )
        if not ok:
            return JSONResponse(
                status_code=409,
                content={
                    "conflict": True,
                    "message": "El archivo fue modificado externamente (Obsidian u otro proceso).",
                    "disk_content": disk_content,
                    "disk_mtime": new_mtime,
                },
            )
        return {"ok": True, "mtime": new_mtime}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_name}/create")
async def create_item(org_name: str, body: CreateFileRequest):
    """Crea un archivo nuevo o una carpeta."""
    try:
        mgr = _get_manager()
        if body.is_folder:
            await run_in_threadpool(mgr.create_folder, org_name, body.path)
            return {"ok": True, "path": body.path, "type": "dir"}
        else:
            mtime = await run_in_threadpool(mgr.create_file, org_name, body.path, body.content)
            return {"ok": True, "path": body.path, "mtime": mtime}
    except FileExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{org_name}/file")
async def delete_file(org_name: str, path: str = Query(...)):
    """Elimina un archivo o carpeta vacía."""
    try:
        mgr = _get_manager()
        await run_in_threadpool(mgr.delete_file, org_name, path)
        return {"ok": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except OSError as e:
        raise HTTPException(status_code=400, detail=f"No se puede eliminar: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_name}/fill-from-scans")
async def fill_bitacora_from_scans(org_name: str):
    """
    Crea notas de bitácora para todos los escaneos completados que aún no tienen nota.
    No sobreescribe notas existentes.
    """
    try:
        mgr = _get_manager()
        result = await run_in_threadpool(mgr.fill_from_scans, org_name, storage.db_path)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_name}/new-vector")
async def new_vector(org_name: str, body: NewVectorRequest):
    """
    Crea una nueva nota de vector de acceso a partir de la plantilla CHECKLIST-PENTEST.md.
    Mismo comportamiento que el botón 'Nuevo Vector de Acceso' en Obsidian.
    """
    from datetime import date
    from arsenal.core.bitacora_manager import TEMPLATE_DIR

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre no puede estar vacío.")

    mgr = _get_manager()
    today = date.today().strftime("%Y-%m-%d")
    title = f"{today} - VE - {name}"
    dest_path = f"PENTEST IT OT/Bitacoras/{title}.md"

    # Leer la plantilla desde la carpeta de la org (ya copiada al crear la org)
    template_rel = "PENTEST IT OT/Plantillas/CHECKLIST-PENTEST.md"
    try:
        content, _ = await run_in_threadpool(mgr.read_file, org_name, template_rel)
    except FileNotFoundError:
        # Fallback: plantilla fuente del repo
        src = TEMPLATE_DIR / "PENTEST IT OT" / "Plantillas" / "CHECKLIST-PENTEST.md"
        content = src.read_text(encoding="utf-8") if src.exists() else f"# {title}\n\n"

    # Sustituir la variable de Templater por el título real
    content = content.replace("<% tp.file.title %>", title)
    content = content.replace("<%tp.file.title%>", title)

    try:
        mtime = await run_in_threadpool(mgr.create_file, org_name, dest_path, content)
        return {"ok": True, "path": dest_path, "title": title, "mtime": mtime}
    except FileExistsError:
        raise HTTPException(status_code=409, detail=f"Ya existe un vector con ese nombre: {title}.md")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_name}/rename")
async def rename_item(org_name: str, body: RenameRequest):
    """Renombra o mueve un archivo/carpeta."""
    try:
        mgr = _get_manager()
        await run_in_threadpool(mgr.rename, org_name, body.old_path, body.new_path)
        return {"ok": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except FileExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
