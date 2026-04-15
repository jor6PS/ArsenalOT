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
                 body: dict = None, auth: bool = True) -> dict:
        full_url = f"{self.url}{path}"
        headers  = {"Content-Type": "application/json"}
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            resp = self._session.request(
                method, full_url,
                json=body,
                headers=headers,
                timeout=10,
                allow_redirects=False,   # evitar que redirects eliminen el header Authorization
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
        """Obtiene un token JWT. Devuelve True si tiene éxito."""
        result = self._request("POST", "/api/users/token", {
            "username": self.username,
            "password": self.password,
        }, auth=False)
        token = result.get("datas", {}).get("token")
        if not token:
            raise RuntimeError(f"Autenticación fallida: {result}")
        self._token = token
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
        """Crea un nuevo tipo de vulnerabilidad en la biblioteca de PwnDoc."""
        self._ensure_auth()
        result = self._request("POST", "/api/vulnerabilities", {
            "details": [{
                "locale": locale,
                "title": title,
                "description": description,
                "observation": observation,
                "remediation": remediation,
            }],
            "cvssv3": cvssv3,
            "references": references or [],
            "category": category,
        })
        return result.get("datas", {})

    # ─── Auditorías ────────────────────────────────────────────

    def list_audits(self) -> List[Dict]:
        self._ensure_auth()
        result = self._request("GET", "/api/audits")
        return result.get("datas", [])

    def create_audit(self, name: str, language: str = "es") -> Dict:
        """Crea una nueva auditoría en PwnDoc."""
        self._ensure_auth()
        result = self._request("POST", "/api/audits", {
            "name": name,
            "auditType": "default",
            "language": language,
            "scope": [],
        })
        return result.get("datas", {})

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
