from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from arsenal.web.core.config import templates

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def main_dashboard(request: Request):
    """Dashboard principal de la plataforma ArsenalOT."""
    return templates.TemplateResponse(request, "main.html")

@router.get("/pentest", response_class=HTMLResponse)
async def pentest_orgs_page(request: Request):
    """Página para seleccionar o crear organizaciones."""
    return templates.TemplateResponse(request, "pentest_orgs.html")

@router.get("/pentest/{org_name}", response_class=HTMLResponse)
async def pentest_phases_page(request: Request, org_name: str):
    """Página para seleccionar la fase de ataque de una organización."""
    return templates.TemplateResponse(request, "pentest_phases.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon", response_class=HTMLResponse)
async def recon_dashboard(request: Request, org_name: str):
    """Dashboard de reconocimiento (antiguo dashboard principal)."""
    return templates.TemplateResponse(request, "dashboard.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/scan", response_class=HTMLResponse)
async def recon_scan_page(request: Request, org_name: str):
    """Página de configuración de escaneo."""
    return templates.TemplateResponse(request, "scan.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/results", response_class=HTMLResponse)
async def recon_results_page(request: Request, org_name: str):
    """Página de resultados."""
    return templates.TemplateResponse(request, "results.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/neo4j", response_class=HTMLResponse)
async def recon_neo4j_page(request: Request, org_name: str):
    """Página para exportar a Neo4j."""
    return templates.TemplateResponse(request, "neo4j.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/findings", response_class=HTMLResponse)
async def recon_findings_page(request: Request, org_name: str):
    """Página de findings (vulnerabilidades) integrada con PwnDoc."""
    return templates.TemplateResponse(request, "findings.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/access-vectors", response_class=HTMLResponse)
async def recon_access_vectors_page(request: Request, org_name: str):
    """Diagrama de visibilidad entre orígenes, sistemas y redes."""
    return templates.TemplateResponse(request, "access_vectors.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/exploitation", response_class=HTMLResponse)
async def exploitation_page(request: Request, org_name: str):
    """Página de explotación IT."""
    return templates.TemplateResponse(request, "exploitation.html", {"org_name": org_name})


@router.get("/pentest/{org_name}/exploitation-ot", response_class=HTMLResponse)
async def exploitation_ot_page(request: Request, org_name: str):
    """Página de explotación OT (protocolos industriales)."""
    return templates.TemplateResponse(request, "exploitation_ot.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/bitacora", response_class=HTMLResponse)
async def bitacora_page(request: Request, org_name: str):
    """Página de bitácora Obsidian integrada."""
    return templates.TemplateResponse(request, "bitacora.html", {"org_name": org_name})
