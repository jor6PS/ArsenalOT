from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver
import base64
import time
import os
import requests
import subprocess
import shutil
import tempfile
from pathlib import Path

def take_screenshot(host, port, folder_img_path, driver=None):
    url = f"http://{host}:{port}"
    options = Options()
    options.add_argument("--headless")
    
    local_driver = driver
    should_quit = False
    
    if not local_driver:
        try:
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--window-size=1920,1080")
            os.environ["MOZ_DISABLE_CONTENT_SANDBOX"] = "1"
            local_driver = webdriver.Firefox(options=options)
            should_quit = True
        except Exception as e:
            print(f"⚠️ Error iniciando Firefox: {e}")
            return None
            
    try:
        local_driver.set_page_load_timeout(10)
        local_driver.get(url)
        WebDriverWait(local_driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
    except (TimeoutException, WebDriverException):
        if should_quit:
            local_driver.quit()
        return None
    except Exception:
        if should_quit:
            local_driver.quit()
        return None
    
    time.sleep(1)
    image_file = os.path.join(folder_img_path, f"{host}_{port}.png")
    
    try:
        local_driver.save_screenshot(image_file)
        screenshot_binary = local_driver.get_screenshot_as_png()
        return base64.b64encode(screenshot_binary).decode('utf-8')
    except Exception:
        return None
    finally:
        if should_quit and local_driver:
            local_driver.quit()

def get_source(host, port, folder_src_path):
    urls = [f"http://{host}:{port}", f"https://{host}:{port}"]
    for url in urls:
        try:
            response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            source_file = os.path.join(folder_src_path, f"{host}_{port}.txt")
            with open(source_file, "w", encoding='utf-8') as f:
                f.write(f"<!-- Status: {response.status_code} -->\n")
                f.write(response.text)
            return response.text
        except:
            continue
    return None

def run_eyewitness_batch(targets, img_folder, source_folder):
    """
    Ejecuta EyeWitness en lote para una lista de objetivos.
    targets: Lista de diccionarios [{'ip_address': '...', 'port': 80, 'protocol': 'tcp'}, ...]
    """
    results = {}
    if not targets:
        return results

    for t in targets:
        results[(t['ip_address'], t['port'])] = {"screenshot": None, "source": None}

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_file = os.path.join(tmpdir, "targets.txt")
        with open(targets_file, "w") as f:
            for t in targets:
                # Si es un puerto estándar, pasamos solo la IP para que --prepend-https pruebe ambos protocolos
                if t['port'] in [80, 443]:
                    f.write(f"{t['ip_address']}\n")
                else:
                    f.write(f"http://{t['ip_address']}:{t['port']}\n")
        
        output_dir = os.path.join(tmpdir, "eyewitness_out")
        
        # Ejecutar EyeWitness
        # Utilizamos Xvfb para asegurar que haya un entorno gráfico disponible para el navegador
        # Añadimos --prepend-https para que pruebe HTTP y HTTPS en targets sin protocolo
        cmd = ["xvfb-run", "-a", "eyewitness", "--web", "-f", targets_file, "-d", output_dir, "--no-prompt", "--timeout", "15", "--prepend-https"]
        
        try:
            print(f"🚀 Ejecutando EyeWitness para {len(targets)} objetivos...")
            print(f"📝 Comando: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if process.returncode != 0:
                print(f"⚠️ EyeWitness devolvió código {process.returncode}")
                if process.stderr:
                    print(f"❌ EyeWitness Error: {process.stderr[:500]}")
            
            # Depuración: Listar qué archivos generó EyeWitness
            print(f"📁 Contenido de la salida de EyeWitness ({output_dir}):")
            all_files = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    full_p = os.path.join(root, f)
                    all_files.append(full_p)
                    print(f"  🔍 Encontrado: {full_p}")
            
            # EyeWitness puede usar 'screens' o 'screenshots' dependiendo de la versión
            screens_dir = Path(output_dir) / "screens"
            if not screens_dir.exists():
                screens_dir = Path(output_dir) / "screenshots"
            
            sources_dir = Path(output_dir) / "source"
            if not sources_dir.exists():
                sources_dir = Path(output_dir) / "sources" # Algunos usan plural
            
            for t in targets:
                ip = t['ip_address']
                port = t['port']
                
                # Búsqueda robusta de imágenes
                found_screen = False
                if screens_dir.exists():
                    # Patterns to try:
                    # 1. Standard with port: *ip*port*.png
                    # 2. IP only (for default ports): ip.png, http.ip.png, etc.
                    # 3. IP with underscores: ip_port.png
                    
                    specific_patterns = [
                        f"*{ip}*{port}*.png", 
                        f"*{ip.replace('.', '_')}*_{port}*.png"
                    ]
                    
                    # Si es puerto por defecto, intentar sin el puerto
                    if port in [80, 443]:
                        specific_patterns.extend([
                            f"{ip}.png",
                            f"http.{ip}.png",
                            f"https.{ip}.png",
                            f"*.{ip}.png"
                        ])
                    
                    for pattern in specific_patterns:
                        for screen_file in screens_dir.glob(pattern):
                            try:
                                dest_img = os.path.join(img_folder, f"{ip}_{port}.png")
                                shutil.copy2(screen_file, dest_img)
                                with open(dest_img, "rb") as f:
                                    results[(ip, port)]["screenshot"] = base64.b64encode(f.read()).decode('utf-8')
                                found_screen = True
                                print(f"✅ Capturada imagen para {ip}:{port} desde {screen_file.name}")
                                break
                            except Exception as e:
                                print(f"⚠️ Error procesando screenshot para {ip}: {e}")
                        if found_screen: break

                # Búsqueda robusta de fuentes
                found_src = False
                if sources_dir.exists():
                    # Patterns to try:
                    # 1. Standard with port: *ip*port*.txt
                    # 2. IP only (for default ports): ip.txt, http.ip.txt, etc.
                    # 3. IP with underscores: ip_port.txt
                    
                    specific_src_patterns = [
                        f"*{ip}*{port}*.txt", 
                        f"*{ip.replace('.', '_')}*_{port}*.txt"
                    ]
                    
                    # Si es puerto por defecto, intentar sin el puerto
                    if port in [80, 443]:
                        specific_src_patterns.extend([
                            f"{ip}.txt",
                            f"http.{ip}.txt",
                            f"https.{ip}.txt",
                            f"*.{ip}.txt"
                        ])
                    
                    for pattern in specific_src_patterns:
                        for source_file in sources_dir.glob(pattern):
                            try:
                                dest_src = os.path.join(source_folder, f"{ip}_{port}.txt")
                                shutil.copy2(source_file, dest_src)
                                with open(dest_src, "r", encoding='utf-8', errors='ignore') as f:
                                    results[(ip, port)]["source"] = f.read()
                                found_src = True
                                print(f"✅ Capturado source para {ip}:{port} desde {source_file.name}")
                                break
                            except Exception as e:
                                print(f"⚠️ Error procesando source para {ip}: {e}")
                        if found_src: break
                        
        except subprocess.TimeoutExpired:
            print("⚠️ EyeWitness excedió el tiempo límite.")
        except Exception as e:
            print(f"⚠️ Error ejecutando EyeWitness: {e}")
            
    return results
