from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from arsenal.web.core.config import templates

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def main_dashboard(request: Request):
    """Dashboard principal de la plataforma ArsenalOT."""
    return templates.TemplateResponse("main.html", {"request": request})

@router.get("/pentest", response_class=HTMLResponse)
async def pentest_orgs_page(request: Request):
    """Página para seleccionar o crear organizaciones."""
    return templates.TemplateResponse("pentest_orgs.html", {"request": request})

@router.get("/pentest/{org_name}", response_class=HTMLResponse)
async def pentest_phases_page(request: Request, org_name: str):
    """Página para seleccionar la fase de ataque de una organización."""
    return templates.TemplateResponse("pentest_phases.html", {"request": request, "org_name": org_name})

@router.get("/pentest/{org_name}/recon", response_class=HTMLResponse)
async def recon_dashboard(request: Request, org_name: str):
    """Dashboard de reconocimiento (antiguo dashboard principal)."""
    return templates.TemplateResponse("dashboard.html", {"request": request, "org_name": org_name})

@router.get("/pentest/{org_name}/recon/scan", response_class=HTMLResponse)
async def recon_scan_page(request: Request, org_name: str):
    """Página de configuración de escaneo."""
    return templates.TemplateResponse("scan.html", {"request": request, "org_name": org_name})

@router.get("/pentest/{org_name}/recon/results", response_class=HTMLResponse)
async def recon_results_page(request: Request, org_name: str):
    """Página de resultados."""
    return templates.TemplateResponse("results.html", {"request": request, "org_name": org_name})

@router.get("/pentest/{org_name}/recon/neo4j", response_class=HTMLResponse)
async def recon_neo4j_page(request: Request, org_name: str):
    """Página para exportar a Neo4j."""
    return templates.TemplateResponse("neo4j.html", {"request": request, "org_name": org_name})
