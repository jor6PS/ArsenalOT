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

@router.get("/guias", response_class=HTMLResponse)
async def guides_page(request: Request):
    """Pagina de guias de auditoria en solo lectura."""
    return templates.TemplateResponse(request, "guides.html")

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

@router.get("/pentest/{org_name}/recon/finding-candidates", response_class=HTMLResponse)
async def recon_finding_candidates_page(request: Request, org_name: str):
    """Pantalla de hallazgos candidatos para revision del auditor."""
    return templates.TemplateResponse(request, "finding_candidates.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/visibility-diagram", response_class=HTMLResponse)
async def recon_visibility_diagram_page(request: Request, org_name: str):
    """Diagrama de visibilidad entre orígenes, sistemas y redes."""
    return templates.TemplateResponse(request, "visibility_diagram.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/global-map", response_class=HTMLResponse)
async def recon_global_map_page(request: Request, org_name: str):
    """Mapa global jerárquico de organización, sistemas, redes, assets y servicios."""
    return templates.TemplateResponse(request, "global_map.html", {"org_name": org_name})

@router.get("/pentest/{org_name}/recon/attack-path", response_class=HTMLResponse)
async def recon_attack_path_page(request: Request, org_name: str):
    """Diagrama de caminos de ataque hacia un asset objetivo."""
    return templates.TemplateResponse(request, "attack_path.html", {"org_name": org_name})

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
