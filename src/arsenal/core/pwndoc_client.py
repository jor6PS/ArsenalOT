"""
Cliente para la API REST de PwnDoc.

Variables de entorno:
  PWNDOC_URL      → URL base del backend de PwnDoc (por defecto https://localhost:4242)
  PWNDOC_USER     → Usuario admin (por defecto 'admin')
  PWNDOC_PASSWORD → Contraseña admin (por defecto 'changeme')
"""

import os
import requests
import urllib3
from typing import Optional, List, Dict

# Suprimir warnings de certificados autofirmados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PWNDOC_URL      = os.environ.get("PWNDOC_URL",      "https://localhost:4242")
PWNDOC_USER     = os.environ.get("PWNDOC_USER",     "admin")
PWNDOC_PASSWORD = os.environ.get("PWNDOC_PASSWORD", "changeme")


class PwnDocClient:
    """Wraps PwnDoc's REST API with JWT auth."""

    def __init__(self, url: str = None, username: str = None, password: str = None):
        self.url      = (url or PWNDOC_URL).rstrip("/")
        self.username = username or PWNDOC_USER
        self.password = password or PWNDOC_PASSWORD
        self._token: Optional[str] = None

        # Sesión persistente: misma conexión para auth + llamadas posteriores,
        # SSL permisivo para certificados autofirmados.
        self._session = requests.Session()
        self._session.verify = False

    # ─── HTTP helper ───────────────────────────────────────────

    def _request(self, method: str, path: str,
                 body=None, auth: bool = True) -> dict:
        full_url = f"{self.url}{path}"

        # El token se almacena en la sesión tras authenticate(); los headers de sesión
        # se reenvían automáticamente en redirects al mismo host, por lo que no hace
        # falta allow_redirects=False ni añadir el header manualmente por petición.
        try:
            resp = self._session.request(
                method, full_url,
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"PwnDoc {method} {path} → conexión fallida: {exc}") from exc

        if not resp.ok:
            raise RuntimeError(
                f"PwnDoc {method} {path} → HTTP {resp.status_code}: {resp.text}"
            )

        try:
            return resp.json()
        except ValueError:
            return {}

    # ─── Auth ──────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """Obtiene un token JWT y lo almacena en la sesión. Devuelve True si tiene éxito."""
        result = self._request("POST", "/api/users/token", {
            "username": self.username,
            "password": self.password,
        }, auth=False)
        token = result.get("datas", {}).get("token")
        if not token:
            raise RuntimeError(f"Autenticación fallida: {result}")
        self._token = token
        # Guardar en sesión para que se reenvíe en redirects automáticamente
        self._session.headers["Authorization"] = f"Bearer {token}"
        return True

    def _ensure_auth(self):
        if not self._token:
            self.authenticate()

    def ping(self) -> bool:
        """Devuelve True si PwnDoc está accesible y las credenciales son válidas."""
        try:
            self.authenticate()
            return True
        except Exception:
            return False

    # ─── Biblioteca de vulnerabilidades ────────────────────────

    def list_vulnerabilities(self) -> List[Dict]:
        """Lista todos los tipos de vulnerabilidades de la biblioteca."""
        self._ensure_auth()
        result = self._request("GET", "/api/vulnerabilities")
        return result.get("datas", [])

    def create_vulnerability(
        self,
        title: str,
        description: str = "",
        observation: str = "",
        remediation: str = "",
        locale: str = "es",
        category: str = "",
        cvssv3: str = "",
        references: list = None,
    ) -> Dict:
        """Crea un nuevo tipo de vulnerabilidad en la biblioteca de PwnDoc.

        El endpoint POST /api/vulnerabilities espera un array de objetos
        (importación masiva). Enviamos array de un solo elemento.
        Respuesta: {"created": N, "duplicates": N}
        """
        self._ensure_auth()
        vuln: dict = {
            "details": [{
                "locale": locale,
                "title": title,
                "description": description,
                "observation": observation,
                "remediation": remediation,
            }],
            "cvssv3": cvssv3,
            "references": references or [],
        }
        # category vacío provoca created:0 en PwnDoc; solo incluirlo si hay valor
        if category:
            vuln["category"] = category
        payload = [vuln]
        result = self._request("POST", "/api/vulnerabilities", payload)
        datas = result.get("datas", {})

        # El endpoint no devuelve el _id del elemento creado; lo buscamos por título.
        if datas.get("created", 0) > 0:
            for vuln in self.list_vulnerabilities():
                details = vuln.get("details", [])
                match = next((d for d in details if d.get("title") == title), None)
                if match:
                    return vuln
        return datas

    # ─── Auditorías ────────────────────────────────────────────

    def list_audit_types(self) -> List[Dict]:
        """Lista los tipos de auditoría disponibles en PwnDoc."""
        self._ensure_auth()
        result = self._request("GET", "/api/data/audit-types")
        return result.get("datas", [])

    def _first_audit_type(self) -> str:
        """Devuelve el nombre del primer audit type disponible, o lanza excepción si no hay ninguno."""
        types = self.list_audit_types()
        if not types:
            raise RuntimeError(
                "PwnDoc no tiene ningún auditType configurado. "
                "Crea al menos uno desde la interfaz de PwnDoc antes de usar esta función."
            )
        return types[0]["name"]

    def list_audits(self) -> List[Dict]:
        self._ensure_auth()
        result = self._request("GET", "/api/audits")
        return result.get("datas", [])

    def create_audit(self, name: str, language: str = "es",
                     audit_type: str = None) -> Dict:
        """Crea una nueva auditoría en PwnDoc.

        Si audit_type no se especifica, usa el primer auditType disponible.
        """
        self._ensure_auth()
        if audit_type is None:
            audit_type = self._first_audit_type()
        result = self._request("POST", "/api/audits", {
            "name": name,
            "auditType": audit_type,
            "language": language,
            "scope": [],
        })
        datas = result.get("datas", {})
        # Response: {"message": "...", "audit": {_id, name, ...}}
        return datas.get("audit") or datas

    def get_audit_by_name(self, name: str) -> Optional[Dict]:
        """Devuelve la primera auditoría cuyo nombre coincida (insensible a mayúsculas)."""
        for audit in self.list_audits():
            if audit.get("name", "").lower() == name.lower():
                return audit
        return None

    def ensure_audit(self, name: str, language: str = "es") -> str:
        """
        Devuelve el _id de la auditoría con ese nombre.
        Si no existe, la crea.
        """
        existing = self.get_audit_by_name(name)
        if existing:
            return str(existing.get("_id") or existing.get("id"))
        created = self.create_audit(name, language)
        return str(created.get("_id") or created.get("id"))

    # ─── Findings ──────────────────────────────────────────────

    def add_finding(
        self,
        audit_id: str,
        title: str,
        description: str = "",
        observation: str = "",
        remediation: str = "",
        cvssv3: str = "",
        vuln_type_id: str = None,
    ) -> Dict:
        """Añade un hallazgo a una auditoría de PwnDoc."""
        self._ensure_auth()
        payload: dict = {
            "title":       title,
            "description": description,
            "observation": observation,
            "remediation": remediation,
            "cvssv3":      cvssv3,
            "references":  [],
            "poc":         "",
            "status":      0,
        }
        if vuln_type_id:
            payload["vulnType"] = vuln_type_id
        result = self._request("POST", f"/api/audits/{audit_id}/findings", payload)
        return result.get("datas", {})

    def get_findings(self, audit_id: str) -> List[Dict]:
        """Lista los hallazgos de una auditoría."""
        self._ensure_auth()
        result = self._request("GET", f"/api/audits/{audit_id}")
        audit_data = result.get("datas", {})
        return audit_data.get("findings", [])
