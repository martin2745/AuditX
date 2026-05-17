# =============================================================================
# AuditX - fingerprinting/web.py
# =============================================================================
# Fingerprinting de servicios web (HTTP / HTTPS) mediante curl y whatweb.
# Detecta servidor web, CMS, stack tecnológico y cabeceras de seguridad.
# =============================================================================

import re
from configuracion import Colores, TIMEOUT_HTTP, TIMEOUT_WHATWEB, WHATWEB_AGRESIVIDAD
from .base import ejecutar_comando, agregar_tecnologia


def fingerprint_web(objetivo: str, puerto: int, tipo: str, resultados: dict):
    """Fingerprinting de servicios web mediante curl y whatweb."""
    esquema = "https" if tipo == "https" else "http"
    url = (
        f"{esquema}://{objetivo}"
        if puerto in (80, 443)
        else f"{esquema}://{objetivo}:{puerto}"
    )
    resultados["urls_analizadas"].append(url)

    info = {"url": url, "servidor": None, "cms": None, "tecnologias": [], "cabeceras_seguridad": {}}

    _analizar_cabeceras(url, resultados, info)
    _analizar_whatweb(url, resultados, info)

    resultados["servicios"][f"{tipo}:{puerto}"] = info


# =============================================================================
# Análisis de cabeceras HTTP
# =============================================================================

def _analizar_cabeceras(url: str, resultados: dict, info: dict):
    cmd = ["curl", "-s", "-I", "--max-time", str(TIMEOUT_HTTP), "--insecure", url]
    try:
        salida = ejecutar_comando(cmd)
        resultados["salida_raw"] += salida

        cabeceras = _parsear_cabeceras(salida)
        resultados["cabeceras"].update(cabeceras)

        seg = _verificar_cabeceras_seguridad(cabeceras)
        for k in ("presentes", "ausentes"):
            resultados["cabeceras_seguridad"][k] = list(set(
                resultados["cabeceras_seguridad"][k] + seg[k]
            ))
        info["cabeceras_seguridad"] = seg

        if "server" in cabeceras:
            resultados["servidor_web"] = cabeceras["server"]
            info["servidor"] = cabeceras["server"]

        _detectar_cms_cabeceras(cabeceras, resultados, info)

    except Exception as e:
        resultados["errores"].append(f"Error analizando cabeceras de {url}: {str(e)}")


def _parsear_cabeceras(respuesta_raw: str) -> dict:
    cabeceras = {}
    for linea in respuesta_raw.splitlines():
        if ":" in linea and not linea.startswith("HTTP/"):
            clave, _, valor = linea.partition(":")
            cabeceras[clave.strip().lower()] = valor.strip()
    return cabeceras


def _verificar_cabeceras_seguridad(cabeceras: dict) -> dict:
    """Verifica cabeceras de seguridad HTTP recomendadas (OWASP A05)."""
    requeridas = {
        "strict-transport-security": "HSTS",
        "x-content-type-options"   : "X-Content-Type-Options",
        "x-frame-options"          : "X-Frame-Options",
        "content-security-policy"  : "CSP",
        "x-xss-protection"         : "X-XSS-Protection",
        "referrer-policy"          : "Referrer-Policy",
    }
    presentes, ausentes = [], []
    for cabecera, nombre in requeridas.items():
        (presentes if cabecera in cabeceras else ausentes).append(nombre)
    return {"presentes": presentes, "ausentes": ausentes}


def _detectar_cms_cabeceras(cabeceras: dict, resultados: dict, info: dict):
    if "composed-by" in cabeceras:
        m = re.search(r"SPIP\s+([\d.]+)", cabeceras["composed-by"], re.IGNORECASE)
        if m:
            resultados["cms"] = info["cms"] = "SPIP"
            resultados["version_cms"] = m.group(1)
            agregar_tecnologia(f"SPIP {m.group(1)}", resultados, info)

    if "x-powered-by" in cabeceras:
        agregar_tecnologia(cabeceras["x-powered-by"], resultados, info)


# =============================================================================
# Análisis con whatweb
# =============================================================================

def _analizar_whatweb(url: str, resultados: dict, info: dict):
    cmd = ["whatweb", "--no-errors", "-a", str(WHATWEB_AGRESIVIDAD), url]
    try:
        salida = ejecutar_comando(cmd, timeout=TIMEOUT_WHATWEB)
        resultados["salida_raw"] += "\n" + salida
        _parsear_salida_whatweb(salida, resultados, info)
    except FileNotFoundError:
        resultados["errores"].append("whatweb no encontrado. Instalar con: apt install whatweb")
    except Exception as e:
        resultados["errores"].append(f"Error en whatweb para {url}: {str(e)}")


def _parsear_salida_whatweb(salida: str, resultados: dict, info: dict):
    patron = re.compile(r"([A-Za-z][\w\-\.]+)\[([^\]]+)\]")
    coincidencias = patron.findall(salida)

    for nombre, version in coincidencias:
        agregar_tecnologia(f"{nombre} {version}", resultados, info)

    if not resultados["cms"]:
        cms_conocidos = ("SPIP", "WordPress", "Joomla", "Drupal", "Magento")

        # Primera pasada: nombre exacto (ej: "WordPress[5.8.1]")
        for nombre, version in coincidencias:
            for cms in cms_conocidos:
                if nombre.lower() == cms.lower():
                    resultados["cms"] = info["cms"] = cms
                    resultados["version_cms"] = version
                    break
            if resultados["cms"]:
                break

        # Segunda pasada: nombre parcial como fallback (ej: "WordPress-Login[1.0]")
        if not resultados["cms"]:
            for nombre, version in coincidencias:
                for cms in cms_conocidos:
                    if cms.lower() in nombre.lower():
                        resultados["cms"] = info["cms"] = cms
                        resultados["version_cms"] = version
                        break
                if resultados["cms"]:
                    break
