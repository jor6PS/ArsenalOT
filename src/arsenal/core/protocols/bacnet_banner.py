# -*- coding: utf-8 -*-
import sys
from socket import *
import binascii

def BACnet(nObj, HST, port, tramaX):
    """ Realiza una solicitud BACnet y devuelve la respuesta para un objeto específico """
    objBnet = ''
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((HST, int(port)))  # Conectar al host y puerto

    sndFrm = tramaX[nObj]
    s.send(sndFrm)  # Enviar la trama
    dump = s.recv(2048)  # Recibir la respuesta

    # Procesar la respuesta según el objeto
    if (nObj == 1):  # Instance ID como un número entero
        objBnet = int(binascii.hexlify(dump[19:-1]), 16)  # Convertir a hex y a entero
    else:
        objBnet = dump[19:-1].decode('utf-8')  # Decodificar a cadena

    s.close()
    return objBnet


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
        strBacnet = BACnet(objN, host, 47808, tramaX)  # Llamar a BACnet para obtener la respuesta
        desc = _bacnet_obj_description[objN]  # Descripción del objeto
        result.append(f" [+] {desc}: \t    {strBacnet}")  # Almacenar el resultado

    return "\n".join(result)  # Retornar todos los resultados como una cadena
