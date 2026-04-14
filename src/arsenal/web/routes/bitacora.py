"""
API routes para la bitácora Obsidian integrada.
"""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
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


# ── Endpoints ────────────────────────────────────────────────

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
        tree = mgr.get_file_tree(org_name)
        return {"tree": tree}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{org_name}/file")
async def read_file(org_name: str, path: str = Query(..., description="Ruta relativa al dir de la org")):
    """Lee un archivo de la bitácora."""
    try:
        mgr = _get_manager()
        content, mtime = mgr.read_file(org_name, path)
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
        ok, disk_content, new_mtime = mgr.write_file(
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
            mgr.create_folder(org_name, body.path)
            return {"ok": True, "path": body.path, "type": "dir"}
        else:
            mtime = mgr.create_file(org_name, body.path, body.content)
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
        mgr.delete_file(org_name, path)
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
        result = mgr.fill_from_scans(org_name, storage.db_path)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_name}/rename")
async def rename_item(org_name: str, body: RenameRequest):
    """Renombra o mueve un archivo/carpeta."""
    try:
        mgr = _get_manager()
        mgr.rename(org_name, body.old_path, body.new_path)
        return {"ok": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except FileExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
