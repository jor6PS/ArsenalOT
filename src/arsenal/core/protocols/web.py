from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver
import base64
import time
import os
import requests

def take_screenshot(host, port, folder_img_path):
    url = f"http://{host}:{port}"
    options = Options()
    options.add_argument("--headless")  # Ejecuta el navegador en modo sin interfaz gráfica
    driver = None
    
    try:
        # Configura el driver de Firefox y carga la página
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(10)
        driver.get(url)
        WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
    except (TimeoutException, WebDriverException) as e:
        # Maneja errores de carga de página
        if driver:
            driver.quit()
        return None
    except Exception as e:
        # Maneja cualquier otro error (driver no disponible, etc.)
        if driver:
            driver.quit()
        return None
    
    if not driver:
        return None
    
    time.sleep(1)  # Espera 1 segundo antes de tomar la captura
    image_file = os.path.join(folder_img_path, f"{host}_{port}.png")
    
    if os.path.exists(image_file):
        # Verifica si el archivo de la captura ya existe
        driver.quit()
        return None
    
    try:
        # Toma la captura de pantalla y la guarda como archivo PNG
        driver.save_screenshot(image_file)
        screenshot_binary = driver.get_screenshot_as_png()
        return base64.b64encode(screenshot_binary).decode('utf-8')
    except Exception as e:
        # Maneja errores al guardar la captura
        return None
    finally:
        if driver:
            driver.quit()  # Cierra el navegador

def get_source(host, port, folder_src_path):
    # Intentar HTTP y HTTPS
    urls = [f"http://{host}:{port}", f"https://{host}:{port}"]
    
    for url in urls:
        try:
            # Realiza una solicitud HTTP para obtener el código fuente
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            if response.status_code == 200:
                source_file = os.path.join(folder_src_path, f"{host}_{port}.txt")
                if not os.path.exists(source_file):
                    with open(source_file, "w", encoding='utf-8') as f:
                        f.write(response.text)  # Guarda el código fuente en un archivo
                return response.text
        except requests.Timeout:
            continue  # Intentar siguiente URL
        except requests.RequestException:
            continue  # Intentar siguiente URL
        except Exception:
            continue  # Intentar siguiente URL
    
    return None
