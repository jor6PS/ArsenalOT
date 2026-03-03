from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.support.ui import WebDriverWait
from selenium import webdriver
import base64
import time
import os
import requests
import logging

logger = logging.getLogger(__name__)

def take_screenshot(host, port, folder_img_path):
    """Toma una captura de pantalla de un servicio web."""
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
        logger.warning(f"Error al cargar {url}: {e}")
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return None
    except Exception as e:
        logger.error(f"Error inesperado al inicializar driver para {url}: {e}")
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return None
    
    time.sleep(1)  # Espera 1 segundo antes de tomar la captura
    image_file = os.path.join(folder_img_path, f"{host}_{port}.png")
    
    if os.path.exists(image_file):
        # Verifica si el archivo de la captura ya existe
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return None
    
    try:
        # Toma la captura de pantalla y la guarda como archivo PNG
        driver.save_screenshot(image_file)
        screenshot_binary = driver.get_screenshot_as_png()
        return base64.b64encode(screenshot_binary).decode('utf-8')
    except Exception as e:
        logger.error(f"Error al guardar captura para {url}: {e}")
        return None
    finally:
        if driver:
            try:
                driver.quit()  # Cierra el navegador
            except Exception as e:
                logger.warning(f"Error al cerrar driver: {e}")

def get_source(host, port, folder_src_path):
    """Obtiene el código fuente HTML de un servicio web."""
    url = f"http://{host}:{port}"
    try:
        # Realiza una solicitud HTTP para obtener el código fuente
        response = requests.get(url, timeout=5, allow_redirects=True)
        if response.status_code != 200:
            logger.warning(f"HTTP {response.status_code} para {url}")
            return None
        
        source_file = os.path.join(folder_src_path, f"{host}_{port}.txt")
        if os.path.exists(source_file):
            # Verifica si el archivo de código fuente ya existe
            return response.text
        
        os.makedirs(folder_src_path, exist_ok=True)
        with open(source_file, "w", encoding='utf-8') as f:
            f.write(response.text)  # Guarda el código fuente en un archivo
        return response.text
    except requests.Timeout:
        # Maneja un error de timeout al intentar obtener el código fuente
        logger.warning(f"Timeout al obtener código fuente de {url}")
        return None
    except requests.RequestException as e:
        # Maneja otros errores de conexión
        logger.warning(f"Error de conexión al obtener código fuente de {url}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error inesperado al obtener código fuente de {url}: {e}")
        return None
