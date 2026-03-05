from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver
import base64
import time
import os
import requests

def take_screenshot(host, port, folder_img_path, driver=None):
    url = f"http://{host}:{port}"
    options = Options()
    options.add_argument("--headless")  # Ejecuta el navegador en modo sin interfaz gráfica
    
    # Si ya tenemos un driver, lo usamos. Si no, creamos uno nuevo.
    local_driver = driver
    should_quit = False
    
    if not local_driver:
        try:
            local_driver = webdriver.Firefox(options=options)
            should_quit = True
        except Exception:
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
    
    time.sleep(1)  # Espera 1 segundo antes de tomar la captura
    image_file = os.path.join(folder_img_path, f"{host}_{port}.png")
    
    if os.path.exists(image_file):
        if should_quit:
            local_driver.quit()
        return None
    
    try:
        # Toma la captura de pantalla y la guarda como archivo PNG
        local_driver.save_screenshot(image_file)
        screenshot_binary = local_driver.get_screenshot_as_png()
        return base64.b64encode(screenshot_binary).decode('utf-8')
    except Exception:
        return None
    finally:
        if should_quit and local_driver:
            local_driver.quit()  # Cierra el navegador solo si lo creamos nosotros 

def get_source(host, port, folder_src_path):
    # Intentar HTTP y HTTPS
    urls = [f"http://{host}:{port}", f"https://{host}:{port}"]
    
    for url in urls:
        try:
            # Realiza una solicitud HTTP para obtener el código fuente
            # Bajamos timeout a 3s para check rápido y aceptamos cualquier status
            response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            
            # Si recibimos cualquier respuesta (incluso 401, 403, 404, 500), es un puerto web
            source_file = os.path.join(folder_src_path, f"{host}_{port}.txt")
            if not os.path.exists(source_file):
                with open(source_file, "w", encoding='utf-8') as f:
                    # Incluimos el status code en el archivo para debug
                    f.write(f"<!-- Status: {response.status_code} -->\n")
                    f.write(response.text)
            return response.text
            
        except requests.Timeout:
            continue  # Intentar siguiente URL
        except requests.RequestException:
            continue  # Intentar siguiente URL
        except Exception:
            continue  # Intentar siguiente URL
    
    return None
