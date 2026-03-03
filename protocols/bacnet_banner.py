# -*- coding: utf-8 -*-
from socket import *
import binascii
import logging

logger = logging.getLogger(__name__)

TIMEOUT = 3

def BACnet(nObj, HST, port, tramaX):
    """ Realiza una solicitud BACnet y devuelve la respuesta para un objeto específico """
    objBnet = ''
    s = None
    try:
        s = socket(AF_INET, SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.connect((HST, int(port)))  # Conectar al host y puerto

        if nObj not in tramaX:
            logger.warning(f"Objeto BACnet {nObj} no encontrado en tramaX")
            return None

        sndFrm = tramaX[nObj]
        s.send(sndFrm)  # Enviar la trama
        dump = s.recv(2048)  # Recibir la respuesta

        if not dump or len(dump) < 20:
            logger.warning(f"Respuesta BACnet demasiado corta de {HST}")
            return None

        # Procesar la respuesta según el objeto
        if nObj == 1:  # Instance ID como un número entero
            try:
                objBnet = int(binascii.hexlify(dump[19:-1]), 16)  # Convertir a hex y a entero
            except (ValueError, IndexError) as e:
                logger.warning(f"Error parseando Instance ID de {HST}: {e}")
                return None
        else:
            try:
                objBnet = dump[19:-1].decode('utf-8', errors='replace')  # Decodificar a cadena
            except (UnicodeDecodeError, IndexError) as e:
                logger.warning(f"Error decodificando objeto BACnet de {HST}: {e}")
                return None

        return objBnet
    except timeout as e:
        logger.warning(f"Timeout al obtener objeto BACnet {nObj} de {HST}")
        return None
    except OSError as e:
        logger.warning(f"Error de red al obtener objeto BACnet {nObj} de {HST}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error inesperado al obtener objeto BACnet {nObj} de {HST}: {e}")
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def bacnet_banner(host):
    """ Obtiene la información de los objetos BACnet de un dispositivo """
    
    # Descripción de los objetos BACnet
    _bacnet_obj_description = { 
        0: "Vendor Name",  
        1: "Instance ID",  
        2: "Firmware",     
        3: "Apps Software",
        4: "Object Name",  
        5: "Model Name",   
        6: "Description",
        7: "Location"
    }

    # Encabezado que se usará en las solicitudes BACnet
    hder = b"\x81\x0a\x00\x11\x01\x04\x00\x05\x01\x0c\x0c\x02\x3f\xff\xff\x19"

    # Definición de las tramas BACnet
    tramaX = {
        0: hder + b"\x79",
        1: hder + b"\x4b",
        2: hder + b"\x2C",
        3: hder + b"\x0C",
        4: hder + b"\x4D",
        5: hder + b"\x46",
        6: hder + b"\x1c",
        7: hder + b"\x3a"
    }

    result = []
    totFRm = len(tramaX)  # Total de objetos a solicitar

    # Realizar la consulta BACnet para cada objeto
    for objN in range(totFRm):
        try:
            strBacnet = BACnet(objN, host, 47808, tramaX)  # Llamar a BACnet para obtener la respuesta
            desc = _bacnet_obj_description.get(objN, f"Unknown {objN}")  # Descripción del objeto
            if strBacnet is not None:
                result.append(f" [+] {desc}: \t    {strBacnet}")  # Almacenar el resultado
            else:
                result.append(f" [-] {desc}: \t    [No disponible]")
        except Exception as e:
            logger.warning(f"Error obteniendo objeto BACnet {objN} de {host}: {e}")
            desc = _bacnet_obj_description.get(objN, f"Unknown {objN}")
            result.append(f" [-] {desc}: \t    [Error]")

    if not result:
        logger.warning(f"No se pudo obtener información BACnet de {host}")
        return None
    
    return "\n".join(result)  # Retornar todos los resultados como una cadena
