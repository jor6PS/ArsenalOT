from pathlib import Path
from fastapi.templating import Jinja2Templates

# Rutas absolutas para encontrar static y templates desde cualquier lugar
file_var = globals().get("__" + "file" + "__")
if file_var:
    BASE_DIR = Path(file_var).resolve().parent.parent
else:
    BASE_DIR = Path.cwd() / "src" / "arsenal" / "web"

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Configurar templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
