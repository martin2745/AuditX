# =============================================================================
# AuditX - fingerprinting/rdp.py
# =============================================================================
# Fingerprinting del servicio RDP: detección del nivel de cifrado y
# configuración de seguridad mediante nmap scripts.
# =============================================================================

from .base import ejecutar_nmap_script, agregar_tecnologia


def fingerprint_rdp(objetivo: str, puerto: int, resultados: dict):
    """Información de RDP mediante nmap scripts."""
    info = {}

    salida = ejecutar_nmap_script(objetivo, puerto, "rdp-enum-encryption")
    if salida:
        resultados["salida_raw"] += salida
        info["nmap_info"] = salida.strip()
        agregar_tecnologia(f"RDP (puerto {puerto})", resultados)

    resultados["servicios"][f"rdp:{puerto}"] = info
