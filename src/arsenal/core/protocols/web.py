"""
Módulo de captura web usando EyeWitness.

EyeWitness gestiona su propio navegador (Chromium), realiza la captura de
pantalla y guarda el código fuente renderizado en un único paso por objetivo.
"""

import base64
import glob
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Caché del ejecutable para no buscar en cada llamada
_EW_BIN = None


def _get_eyewitness_bin():
    """
    Localiza el ejecutable de EyeWitness.
    Comprueba las rutas habituales en Kali Linux, Debian y el clon de GitHub.
    Devuelve una lista de tokens de comando (para subprocess) o None.
    """
    global _EW_BIN
    if _EW_BIN is not None:
        return _EW_BIN

    # (ruta, es_script_python)
    candidates = [
        ("eyewitness",                               False),
        ("/usr/bin/eyewitness",                      False),
        ("/usr/local/bin/eyewitness",                False),
        ("/opt/eyewitness/Python/EyeWitness.py",     True),
        ("/usr/share/eyewitness/EyeWitness.py",      True),
    ]
    for path, is_script in candidates:
        if is_script:
            if os.path.isfile(path):
                _EW_BIN = ["python3", path]
                return _EW_BIN
        else:
            if shutil.which(path) or os.path.isfile(path):
                _EW_BIN = [path]
                return _EW_BIN
    return None


def _target_url(host, port):
    """Devuelve la URL adecuada para un host:puerto (HTTPS para puertos SSL)."""
    if port in (443, 8443):
        return f"https://{host}:{port}"
    return f"http://{host}:{port}"


def _find_screenshot(directory, host, port):
    """
    Busca el PNG que EyeWitness generó para host:port dentro de directory.
    EyeWitness guarda las capturas en un subdirectorio 'screens/' con el
    nombre derivado de la URL (contiene la IP y el puerto).
    Devuelve la ruta al archivo o None.
    """
    screens_dir = os.path.join(directory, "screens")
    search_dir = screens_dir if os.path.isdir(screens_dir) else directory
    if not os.path.isdir(search_dir):
        return None

    for fname in os.listdir(search_dir):
        if not fname.endswith(".png"):
            continue
        if host in fname and str(port) in fname:
            fpath = os.path.join(search_dir, fname)
            if os.path.getsize(fpath) > 0:
                return fpath

    # Fallback: cualquier PNG válido (útil con --single que genera uno solo)
    pngs = [
        p for p in glob.glob(os.path.join(search_dir, "*.png"))
        if os.path.getsize(p) > 0
    ]
    return pngs[0] if pngs else None


def _find_source(directory, host, port):
    """
    Busca el archivo de código fuente que EyeWitness generó para host:port.
    Devuelve (ruta_archivo, contenido_texto) o (None, None).
    """
    source_subdir = os.path.join(directory, "source")
    search_dir = source_subdir if os.path.isdir(source_subdir) else directory
    if not os.path.isdir(search_dir):
        return None, None

    for fname in os.listdir(search_dir):
        if host in fname and str(port) in fname:
            fpath = os.path.join(search_dir, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    return fpath, f.read()
            except Exception:
                pass
    return None, None


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def take_screenshot(host, port, folder_img_path, driver=None):
    """
    Toma una captura de pantalla de host:port usando EyeWitness.

    El parámetro `driver` se ignora (EyeWitness gestiona su propio Chromium).
    Devuelve la imagen codificada en base64 o None si falla.
    """
    ew = _get_eyewitness_bin()
    if not ew:
        return None

    dest_file = os.path.join(folder_img_path, f"{host}_{port}.png")

    # Si ya existe, devolver directamente
    if os.path.exists(dest_file):
        with open(dest_file, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

    url = _target_url(host, port)
    with tempfile.TemporaryDirectory(prefix="ew_") as tmpdir:
        cmd = ew + [
            "--web", "--single", url,
            "--no-prompt", "--timeout", "10",
            "-d", tmpdir,
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=90, check=False)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            return None

        png_path = _find_screenshot(tmpdir, host, str(port))
        if png_path:
            shutil.copy2(png_path, dest_file)
            with open(dest_file, "rb") as f:
                return base64.b64encode(f.read()).decode("utf-8")

    return None


def get_source(host, port, folder_src_path):
    """
    Obtiene el código fuente HTTP de un servicio web mediante requests.
    EyeWitness también captura fuente, pero esta función ofrece un
    acceso rápido sin lanzar un navegador.
    Guarda el resultado en folder_src_path/{host}_{port}.txt.
    Devuelve el texto de la respuesta o None.
    """
    urls = [f"http://{host}:{port}", f"https://{host}:{port}"]

    for url in urls:
        try:
            response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            source_file = os.path.join(folder_src_path, f"{host}_{port}.txt")
            if not os.path.exists(source_file):
                with open(source_file, "w", encoding="utf-8") as f:
                    f.write(f"<!-- Status: {response.status_code} -->\n")
                    f.write(response.text)
            return response.text
        except requests.Timeout:
            continue
        except requests.RequestException:
            continue
        except Exception:
            continue

    return None


def capture_web_evidence_batch(targets, img_folder, source_folder):
    """
    Captura screenshots y código fuente de múltiples objetivos en una sola
    ejecución de EyeWitness (mucho más eficiente que llamadas individuales).

    Args:
        targets     : lista de dicts con claves 'ip_address', 'port', 'protocol'
        img_folder  : carpeta destino para los archivos PNG
        source_folder: carpeta destino para los archivos de código fuente

    Returns:
        dict  {(ip, port): {'screenshot': base64|None, 'source': texto|None}}
    """
    results = {
        (t["ip_address"], t["port"]): {"screenshot": None, "source": None}
        for t in targets
    }

    ew = _get_eyewitness_bin()
    if not ew or not targets:
        return results

    with tempfile.TemporaryDirectory(prefix="ew_batch_") as tmpdir:
        # Escribir fichero de URLs (una por línea)
        url_file = os.path.join(tmpdir, "urls.txt")
        with open(url_file, "w") as f:
            for t in targets:
                f.write(_target_url(t["ip_address"], t["port"]) + "\n")

        cmd = ew + [
            "--web", "-f", url_file,
            "--no-prompt", "--timeout", "10",
            "--threads", "3",
            "-d", tmpdir,
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=600, check=False)
        except Exception:
            pass

        # Recoger y guardar resultados
        img_folder_path    = Path(img_folder)
        source_folder_path = Path(source_folder)

        for t in targets:
            ip, port = t["ip_address"], t["port"]

            # --- Screenshot ---
            png_path = _find_screenshot(tmpdir, ip, str(port))
            if png_path:
                dest = img_folder_path / f"{ip}_{port}.png"
                shutil.copy2(png_path, dest)
                with open(dest, "rb") as f:
                    results[(ip, port)]["screenshot"] = base64.b64encode(f.read()).decode("utf-8")

            # --- Código fuente ---
            _, source_text = _find_source(tmpdir, ip, str(port))
            if source_text:
                dest_src = source_folder_path / f"{ip}_{port}.txt"
                dest_src.write_text(source_text, encoding="utf-8")
                results[(ip, port)]["source"] = source_text

    return results
