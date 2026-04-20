"""
Rutas API para la integración PwnDoc ↔ ArsenalOT.

Prefijo: /api/pwndoc
"""

from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from arsenal.core.pwndoc_client import PwnDocClient
from arsenal.web.core.deps import storage

router = APIRouter(prefix="/api/pwndoc", tags=["pwndoc"])


def _client() -> PwnDocClient:
    return PwnDocClient()


# ── Pydantic models ────────────────────────────────────────────

class NewVulnRequest(BaseModel):
    title: str
    description: str = ""
    observation: str = ""
    remediation: str = ""
    category: str = ""
    cvssv3: str = ""
    locale: str = "es"


class AddFindingRequest(BaseModel):
    title: str
    description: str = ""
    observation: str = ""
    remediation: str = ""
    cvssv3: str = ""
    vuln_type_id: Optional[str] = None   # ID en la biblioteca PwnDoc (opcional)
    language: str = "es"
    audit_type: Optional[str] = None     # Nombre del auditType PwnDoc


class UpdateFindingRequest(BaseModel):
    title: str
    description: str = ""
    observation: str = ""
    remediation: str = ""
    cvssv3: str = ""
    vuln_type_id: Optional[str] = None


class EnsureAuditRequest(BaseModel):
    audit_name: Optional[str] = None
    language: str = "es"
    audit_type: Optional[str] = None
    scope: list[str] = []
    date_start: str = ""
    date_end: str = ""


# ── Endpoints generales ────────────────────────────────────────

@router.get("/audit-types")
async def list_audit_types():
    """Lista los tipos de auditoría disponibles en PwnDoc."""
    try:
        client = _client()
        types = client.list_audit_types()
        if not types:
            client.ensure_default_audit_type()
            types = client.list_audit_types()
        return {"ok": True, "audit_types": [{"name": t["name"]} for t in types]}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error PwnDoc: {e}")


@router.get("/status")
async def pwndoc_status():
    """Comprueba si PwnDoc está accesible y las credenciales son válidas."""
    c = _client()
    try:
        c.authenticate()
        return {"ok": True, "url": c.url}
    except Exception as e:
        return {"ok": False, "url": c.url, "error": str(e)}


@router.get("/vulntypes")
async def list_vulntypes():
    """Lista la biblioteca de tipos de vulnerabilidades de PwnDoc."""
    try:
        vulns = _client().list_vulnerabilities()
        # Normaliza para simplificar el consumo en el frontend
        items = []
        for v in vulns:
            vuln_id = str(v.get("_id") or v.get("id", ""))
            details = v.get("details", [])
            # Preferir español, luego el primero disponible
            detail = next((d for d in details if d.get("locale") == "es"), None) \
                     or (details[0] if details else {})
            items.append({
                "id":          vuln_id,
                "title":       detail.get("title", "(sin título)"),
                "description": detail.get("description", ""),
                "observation": detail.get("observation", ""),
                "remediation": detail.get("remediation", ""),
                "category":    v.get("category", ""),
                "cvssv3":      v.get("cvssv3", ""),
            })
        return {"ok": True, "vulntypes": items}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error PwnDoc: {e}")


@router.post("/vulntypes")
async def create_vulntype(body: NewVulnRequest):
    """Crea un nuevo tipo de vulnerabilidad en la biblioteca de PwnDoc."""
    try:
        result = _client().create_vulnerability(
            title=body.title,
            description=body.description,
            observation=body.observation,
            remediation=body.remediation,
            locale=body.locale,
            category=body.category,
            cvssv3=body.cvssv3,
        )
        vuln_id = str(result.get("_id") or result.get("id", ""))
        return {"ok": True, "id": vuln_id}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error PwnDoc: {e}")


# ── Endpoints por organización ─────────────────────────────────

@router.post("/{org_name}/ensure-audit")
async def ensure_audit(org_name: str, body: EnsureAuditRequest = None):
    """Crea la auditoría en PwnDoc para esta org si no existe aún."""
    if body is None:
        body = EnsureAuditRequest()
    try:
        c = _client()
        audit_name = (body.audit_name or org_name).strip() or org_name
        audit_type = body.audit_type or c.ensure_default_audit_type()
        audit_id = c.ensure_audit(
            audit_name,
            language=body.language,
            audit_type=audit_type,
            scope=[s.strip() for s in (body.scope or []) if s and s.strip()],
            date_start=body.date_start,
            date_end=body.date_end,
        )
        storage.save_pwndoc_audit_id(org_name, audit_id)
        return {
            "ok": True,
            "audit_id": audit_id,
            "audit_name": audit_name,
            "audit_type": audit_type,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error PwnDoc: {e}")


@router.get("/{org_name}/audit")
async def get_org_audit(org_name: str):
    """Devuelve el enlace ArsenalOT -> PwnDoc para una organización."""
    audit_id = storage.get_pwndoc_audit_id(org_name)
    if not audit_id:
        return {"ok": True, "linked": False, "audit_id": None, "audit": None}
    try:
        audits = _client().list_audits()
        audit = next(
            (a for a in audits if str(a.get("_id") or a.get("id")) == str(audit_id)),
            None,
        )
        return {
            "ok": True,
            "linked": True,
            "audit_id": audit_id,
            "audit": audit,
        }
    except Exception as e:
        return {
            "ok": True,
            "linked": True,
            "audit_id": audit_id,
            "audit": None,
            "warning": str(e),
        }


@router.get("/{org_name}/findings")
async def list_findings(org_name: str):
    """Lista los hallazgos de la auditoría PwnDoc para esta org."""
    audit_id = storage.get_pwndoc_audit_id(org_name)
    if not audit_id:
        return {"ok": True, "findings": [], "audit_id": None}
    try:
        findings = _client().get_findings(audit_id)
        arsenalot_ids = storage.get_arsenalot_pwndoc_finding_ids(org_name)
        for finding in findings:
            finding_id = str(finding.get("_id") or finding.get("id") or "")
            finding["arsenalot_added"] = finding_id in arsenalot_ids
        return {"ok": True, "findings": findings, "audit_id": audit_id}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error PwnDoc: {e}")


@router.post("/{org_name}/findings")
async def add_finding(org_name: str, body: AddFindingRequest):
    """
    Añade un hallazgo a la auditoría PwnDoc de la org
    y actualiza la nota VULNERABILIDADES.md de la bitácora.
    """
    # 1. Asegurar que existe auditoría en PwnDoc
    try:
        c = _client()
        audit_id = storage.get_pwndoc_audit_id(org_name)
        if not audit_id:
            audit_type = body.audit_type or c.ensure_default_audit_type()
            audit_id = c.ensure_audit(org_name, language=body.language,
                                      audit_type=audit_type)
            storage.save_pwndoc_audit_id(org_name, audit_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error conectando PwnDoc: {e}")

    # 2. Añadir hallazgo a la auditoría
    try:
        finding = c.add_finding(
            audit_id    = audit_id,
            title       = body.title,
            description = body.description,
            observation = body.observation,
            remediation = body.remediation,
            cvssv3      = body.cvssv3,
            vuln_type_id= body.vuln_type_id,
        )
        finding_id = str(finding.get("_id") or finding.get("id") or "")
        if finding_id:
            storage.save_arsenalot_pwndoc_finding(
                org_name=org_name,
                audit_id=audit_id,
                finding_id=finding_id,
                title=body.title,
            )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error añadiendo finding en PwnDoc: {e}")

    # 3. Actualizar VULNERABILIDADES.md en la bitácora
    try:
        from arsenal.core.bitacora_manager import BitacoraManager
        mgr = BitacoraManager(storage.results_root)
        mgr.add_finding_to_note(
            org_name    = org_name,
            title       = body.title,
            description = body.description,
            observation = body.observation,
            remediation = body.remediation,
        )
    except Exception:
        pass  # No bloquear si falla la bitácora

    return {"ok": True, "audit_id": audit_id, "finding": finding}


@router.put("/{org_name}/findings/{finding_id}")
async def update_finding(org_name: str, finding_id: str, body: UpdateFindingRequest):
    """Actualiza un finding de la auditoría PwnDoc enlazada a esta org."""
    audit_id = storage.get_pwndoc_audit_id(org_name)
    if not audit_id:
        raise HTTPException(status_code=404, detail="No hay auditoría PwnDoc enlazada a esta organización.")
    try:
        result = _client().update_finding(
            audit_id=audit_id,
            finding_id=finding_id,
            title=body.title,
            description=body.description,
            observation=body.observation,
            remediation=body.remediation,
            cvssv3=body.cvssv3,
            vuln_type_id=body.vuln_type_id,
        )
        storage.save_arsenalot_pwndoc_finding(org_name, audit_id, finding_id, body.title)
        return {"ok": True, "audit_id": audit_id, "finding_id": finding_id, "result": result}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error editando finding en PwnDoc: {e}")


@router.delete("/{org_name}/findings/{finding_id}")
async def delete_finding(org_name: str, finding_id: str):
    """Elimina un finding de la auditoría PwnDoc enlazada a esta org."""
    audit_id = storage.get_pwndoc_audit_id(org_name)
    if not audit_id:
        raise HTTPException(status_code=404, detail="No hay auditoría PwnDoc enlazada a esta organización.")
    try:
        result = _client().delete_finding(audit_id, finding_id)
        storage.delete_arsenalot_pwndoc_finding(org_name, finding_id)
        return {"ok": True, "audit_id": audit_id, "finding_id": finding_id, "result": result}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error eliminando finding en PwnDoc: {e}")
