"""
Cliente para la API REST de PwnDoc.

Variables de entorno:
  PWNDOC_URL      → URL base del backend de PwnDoc (por defecto http://localhost:4242)
  PWNDOC_USER     → Usuario admin (por defecto 'admin')
  PWNDOC_PASSWORD → Contraseña admin (por defecto 'changeme')
"""

import os
import json
import urllib.request
import urllib.error
import ssl
from typing import Optional, List, Dict

PWNDOC_URL      = os.environ.get("PWNDOC_URL",      "http://localhost:4242")
PWNDOC_USER     = os.environ.get("PWNDOC_USER",     "admin")
PWNDOC_PASSWORD = os.environ.get("PWNDOC_PASSWORD", "changeme")

# Contexto SSL permisivo para certificados autofirmados
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


class PwnDocClient:
    """Wraps PwnDoc's REST API with JWT auth."""

    def __init__(self, url: str = None, username: str = None, password: str = None):
        self.url      = (url or PWNDOC_URL).rstrip("/")
        self.username = username or PWNDOC_USER
        self.password = password or PWNDOC_PASSWORD
        self._token: Optional[str] = None

    # ─── HTTP helper ───────────────────────────────────────────

    def _request(self, method: str, path: str,
                 body: dict = None, auth: bool = True) -> dict:
        full_url = f"{self.url}{path}"
        data     = json.dumps(body).encode() if body is not None else None
        headers  = {"Content-Type": "application/json"}
        if auth and self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        req = urllib.request.Request(
            full_url, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, context=_ssl_ctx, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"PwnDoc {method} {path} → HTTP {exc.code}: {body_text}"
            ) from exc

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
        # El audit completo incluye findings en result.datas.findings
        audit_data = result.get("datas", {})
        return audit_data.get("findings", [])
