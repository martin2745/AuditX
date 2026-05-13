# =============================================================================
# AuditX - fingerprinting/ftp.py
# =============================================================================
# Fingerprinting del servicio FTP: banner grabbing y comprobación de acceso
# anónimo.
# =============================================================================

import re
import ftplib
from configuracion import Colores, TIMEOUT_SOCKET
from .base import banner_socket, agregar_tecnologia


def fingerprint_ftp(objetivo: str, puerto: int, resultados: dict):
    """Banner grabbing FTP + comprobación de acceso anónimo."""
    info = {"banner": None, "version": None, "anonimo": False, "archivos_raiz": []}

    banner = banner_socket(objetivo, puerto)
    if banner:
        resultados["salida_raw"] += banner
        info["banner"] = banner.strip()
        m = re.search(r"220[- ](.+)", banner)
        if m:
            version = m.group(1).strip()
            info["version"] = version
            agregar_tecnologia(f"FTP {version}", resultados)

    try:
        ftp = ftplib.FTP()
        ftp.connect(objetivo, puerto, timeout=TIMEOUT_SOCKET)
        ftp.login("anonymous", "anonymous@example.com")
        info["anonimo"] = True
        try:
            info["archivos_raiz"] = ftp.nlst()[:20]
        except Exception:
            pass
        ftp.quit()
        print(f"        {Colores.ADVERTENCIA}[!] Login anónimo FTP habilitado{Colores.FIN}")
    except ftplib.error_perm:
        info["anonimo"] = False
    except Exception:
        pass

    resultados["servicios"][f"ftp:{puerto}"] = info
