from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter

class IOXIDResolverScanner:
    """
    Escáner que utiliza el protocolo DCOM para enumerar interfaces de red 
    disponibles en un host Windows remoto.
    Basado en la técnica de IOXIDResolver.
    """
    def __init__(self, target_ip: str = None):
        self.target_ip = target_ip

    def get_interfaces(self, target_ip: str = None):
        """
        Intenta obtener las interfaces de red del host remoto.
        Retorna una lista de direcciones IP descubiertas.
        """
        ip_to_scan = target_ip or self.target_ip
        if not ip_to_scan:
            return []
            
        try:
            # Enlace RPC al puerto 135 (Portmapper/DCOM)
            string_binding = r'ncacn_ip_tcp:%s[135]' % ip_to_scan
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            
            # Ajustar timeouts para evitar bloqueos largos
            rpctransport.set_connect_timeout(5)
            
            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)
            dce.connect()
            
            # Instanciar el exportador de objetos DCOM
            obj_exporter = IObjectExporter(dce)
            
            # Llamar a ServerAlive2 para obtener los bindings
            # Esto devuelve las direcciones IP en las que el servidor está escuchando
            bindings = obj_exporter.ServerAlive2()
            
            discovered_ips = []
            for binding in bindings:
                # Cada binding es un objeto que contiene información de red
                # Extraemos la dirección de red
                network_address = binding['aNetworkAddr'].strip('\x00')
                if network_address and network_address not in discovered_ips:
                    # Filtramos direcciones que no parezcan IPs válidas o sean solo el target original
                    if self._is_valid_discovery(network_address):
                        discovered_ips.append(network_address)
            
            dce.disconnect()
            return discovered_ips
            
        except Exception as e:
            # El error es común si el host no es Windows o no tiene el puerto 135 abierto
            # print(f"DEBUG: Error resolving OXID for {self.target_ip}: {e}")
            return []

    def _is_valid_discovery(self, address: str) -> bool:
        """Filtra resultados que no sean útiles o sean el propio target."""
        # Evitar el hostname si no es IP
        # (Aunque OXID suele devolver IPs o nombres DNS que resuelven localmente)
        if not address:
            return False
        
        # Opcional: Podríamos filtrar el target_ip original, pero suele ser útil 
        # confirmar que aparece en la lista de interfaces.
        return True
