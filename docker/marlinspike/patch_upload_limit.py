"""Apply ArsenalOT deployment defaults to the upstream MarlinSpike image.

MarlinSpike has a global PCAP_MAX_SIZE, but per-user upload_limit_mb defaults
to 200 MB in the upstream application and some upload labels are hardcoded.
This startup patch keeps the upstream image intact while making this
deployment's minimum upload limit explicit.
"""

from __future__ import annotations

import os
from pathlib import Path


DEFAULT_LIMIT_MB = int(os.environ.get("MARLINSPIKE_UPLOAD_LIMIT_MB", "1024"))
APP_DIR = Path("/app")


def replace_in_file(path: Path, replacements: dict[str, str]) -> None:
    text = path.read_text(encoding="utf-8")
    updated = text
    for old, new in replacements.items():
        updated = updated.replace(old, new)
    if updated != text:
        path.write_text(updated, encoding="utf-8")
        print(f"[arsenalot] patched {path}")


def patch_source_defaults() -> None:
    limit = str(DEFAULT_LIMIT_MB)
    replace_in_file(
        APP_DIR / "_auth.py",
        {
            "def create_user(username, password, role=\"user\", upload_limit_mb=200):":
            f"def create_user(username, password, role=\"user\", upload_limit_mb={limit}):",
        },
    )
    replace_in_file(
        APP_DIR / "_models.py",
        {
            "upload_limit_mb = db.Column(db.Integer, nullable=False, default=200)":
            f"upload_limit_mb = db.Column(db.Integer, nullable=False, default={limit})",
        },
    )
    replace_in_file(
        APP_DIR / "app.py",
        {
            "upload_limit_mb INTEGER NOT NULL DEFAULT 200":
            f"upload_limit_mb INTEGER NOT NULL DEFAULT {limit}",
            "else 200)": f"else {limit})",
            "upload_limit = 200": f"upload_limit = {limit}",
        },
    )


def patch_templates() -> None:
    limit = str(DEFAULT_LIMIT_MB)
    replace_in_file(
        APP_DIR / "templates" / "dashboard.html",
        {
            '<span style="font-size:0.82em;color:var(--text-muted);margin-left:8px;">Max 200 MB</span>':
            f'<span id="upload-limit-label" style="font-size:0.82em;color:var(--text-muted);margin-left:8px;">Max {limit} MB</span>',
            f'<span style="font-size:0.82em;color:var(--text-muted);margin-left:8px;">Max {limit} MB</span>':
            f'<span id="upload-limit-label" style="font-size:0.82em;color:var(--text-muted);margin-left:8px;">Max {limit} MB</span>',
            "  // ── Upload ──\n  function setupUpload()":
            f"""  // ── Upload ──
  var uploadLimitMb = {limit};

  function loadUploadLimit() {{
    fetch('/api/profile').then(function(r) {{ return r.json(); }}).then(function(d) {{
      uploadLimitMb = d.upload_limit_mb || {limit};
      var lbl = document.getElementById('upload-limit-label');
      if (lbl) lbl.textContent = 'Max ' + uploadLimitMb + ' MB';
    }}).catch(function() {{}});
  }}

  function setupUpload()""",
            "      loadFiles();\n    });\n    setupUpload();":
            "      loadFiles();\n    });\n    loadUploadLimit();\n    setupUpload();",
            "file.size > 200 * 1024 * 1024": "file.size > uploadLimitMb * 1024 * 1024",
            f"file.size > {limit} * 1024 * 1024": "file.size > uploadLimitMb * 1024 * 1024",
            "File too large (max 200 MB)": "File too large (max ' + uploadLimitMb + ' MB)",
            f"File too large (max {limit} MB)": "File too large (max ' + uploadLimitMb + ' MB)",
        },
    )
    replace_in_file(
        APP_DIR / "templates" / "projects.html",
        {
            "Max 200 MB": f"Max {limit} MB",
            "var uploadLimitMb = 200;": f"var uploadLimitMb = {limit};",
            "d.upload_limit_mb || 200": f"d.upload_limit_mb || {limit}",
        },
    )
    replace_in_file(
        APP_DIR / "templates" / "profile.html",
        {
            "d.upload_limit_mb || 200": f"d.upload_limit_mb || {limit}",
        },
    )
    replace_in_file(
        APP_DIR / "templates" / "users.html",
        {
            'value="200"': f'value="{limit}"',
            "u.upload_limit_mb || 200": f"u.upload_limit_mb || {limit}",
            "|| 200": f"|| {limit}",
        },
    )


def patch_existing_database() -> None:
    try:
        import psycopg2

        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            return
        with psycopg2.connect(database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.tables
                        WHERE table_schema = 'public' AND table_name = 'users'
                    )
                    """
                )
                if not cur.fetchone()[0]:
                    return
                cur.execute(
                    "UPDATE users SET upload_limit_mb = %s WHERE upload_limit_mb < %s",
                    (DEFAULT_LIMIT_MB, DEFAULT_LIMIT_MB),
                )
                cur.execute(
                    f"ALTER TABLE users ALTER COLUMN upload_limit_mb SET DEFAULT {DEFAULT_LIMIT_MB}"
                )
                print(f"[arsenalot] ensured existing MarlinSpike users have >= {DEFAULT_LIMIT_MB} MB upload limit")
    except Exception as exc:
        print(f"[arsenalot] upload limit database patch skipped: {exc}")


if __name__ == "__main__":
    patch_source_defaults()
    patch_templates()
    patch_existing_database()
