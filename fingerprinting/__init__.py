# =============================================================================
# AuditX - fingerprinting/__init__.py
# =============================================================================
# Orquestador de la Fase 2: detecta el tipo de servicio en cada puerto
# abierto y delega en el módulo específico correspondiente.
#
# Para añadir soporte a un nuevo servicio:
#   1. Crea fingerprinting/<servicio>.py con una función fingerprint_<servicio>
#   2. Impórtala aquí y registra el tipo en el despachador _DESPACHADOR
# =============================================================================

from configuracion import Colores, MAPA_SERVICIOS

from .web    import fingerprint_web
from .ssh    import fingerprint_ssh
from .ftp    import fingerprint_ftp
from .mysql  import fingerprint_mysql
from .smb    import fingerprint_smb
from .rdp    import fingerprint_rdp
from .base   import fingerprint_banner_generico


# Mapa tipo_servicio → función de fingerprinting
_DESPACHADOR = {
    "http"    : lambda obj, p, t, r: fingerprint_web(obj, p, t, r),
    "https"   : lambda obj, p, t, r: fingerprint_web(obj, p, t, r),
    "ssh"     : lambda obj, p, t, r: fingerprint_ssh(obj, p, r),
    "ftp"     : lambda obj, p, t, r: fingerprint_ftp(obj, p, r),
    "mysql"   : lambda obj, p, t, r: fingerprint_mysql(obj, p, r),
    "smb"     : lambda obj, p, t, r: fingerprint_smb(obj, p, r),
    "rdp"     : lambda obj, p, t, r: fingerprint_rdp(obj, p, r),
}


def ejecutar_fingerprinting(objetivo: str, puertos: list) -> dict:
    """
    Analiza los servicios presentes en los puertos abiertos del objetivo.

    Args:
        objetivo : IP o hostname del objetivo.
        puertos  : Lista de puertos abiertos (del módulo descubrimiento).

    Returns:
        Diccionario con tecnologías identificadas, banners y detalles por servicio.
    """
    print(f"\n[*] FASE 2 — Fingerprinting de servicios")

    resultados = {
        # Campos de compatibilidad con fases 3 y 4
        "tecnologias"        : [],
        "cabeceras"          : {},
        "cms"                : None,
        "version_cms"        : None,
        "servidor_web"       : None,
        "urls_analizadas"    : [],
        "cabeceras_seguridad": {"presentes": [], "ausentes": []},
        "salida_raw"         : "",
        "errores"            : [],
        # Resultados detallados por servicio
        "servicios"          : {},
    }

    lista_puertos = _normalizar_puertos(puertos)

    if not lista_puertos:
        print(f"    {Colores.ERROR}[!] No hay puertos abiertos para analizar.{Colores.FIN}")
        return resultados

    for puerto, servicio_nmap in lista_puertos:
        tipo = _clasificar_servicio(puerto, servicio_nmap)
        print(f"    [~] Puerto {puerto}/tcp — {tipo}")

        try:
            handler = _DESPACHADOR.get(tipo)
            if handler:
                handler(objetivo, puerto, tipo, resultados)
            else:
                fingerprint_banner_generico(objetivo, puerto, tipo, resultados)
        except Exception as e:
            resultados["errores"].append(f"Error en puerto {puerto} ({tipo}): {str(e)}")

    _imprimir_resumen(resultados)
    return resultados


# =============================================================================
# Utilidades internas del orquestador
# =============================================================================

def _normalizar_puertos(puertos: list) -> list:
    """Convierte la lista de puertos a [(int, servicio_nmap), ...] independientemente del formato de entrada."""
    if not puertos:
        return []
    if isinstance(puertos[0], dict):
        return [(p["puerto"], p.get("servicio", "")) for p in puertos]
    return [(p, "") for p in puertos]


# Variantes de nombres de servicio que devuelve nmap mapeadas a claves internas
_ALIAS_SERVICIOS_NMAP = {
    "http-alt"      : "http",
    "http-proxy"    : "http",
    "ssl/http"      : "https",
    "https-alt"     : "https",
    "microsoft-ds"  : "smb",
    "netbios-ssn"   : "smb",
    "ms-wbt-server" : "rdp",
}

def _clasificar_servicio(puerto: int, servicio_nmap: str = "") -> str:
    """Determina el tipo de servicio priorizando el nombre detectado por nmap."""
    if servicio_nmap:
        nombre = servicio_nmap.lower().strip()
        if nombre in _DESPACHADOR:
            return nombre
        if nombre in _ALIAS_SERVICIOS_NMAP:
            return _ALIAS_SERVICIOS_NMAP[nombre]
    return MAPA_SERVICIOS.get(puerto, "desconocido")


def _imprimir_resumen(resultados: dict):
    print(f"\n    [+] Resumen del fingerprinting:")

    for clave, info in resultados["servicios"].items():
        tipo, puerto = clave.split(":", 1)
        detalle = (
            info.get("version")
            or info.get("banner", "")
            or info.get("url", "")
            or "–"
        )
        if isinstance(detalle, str):
            detalle = detalle[:70]
        print(f"        [{tipo.upper():8s}:{puerto}] {detalle}")

    if resultados["tecnologias"]:
        print(f"\n        Tecnologias identificadas:")
        for tech in resultados["tecnologias"]:
            print(f"          - {tech}")

    seg = resultados.get("cabeceras_seguridad", {})
    if seg.get("ausentes"):
        print(f"\n        [!] Cabeceras HTTP de seguridad ausentes (OWASP A05):")
        for cab in seg["ausentes"]:
            print(f"          - {cab}")

    for error in resultados["errores"]:
        print(f"        {Colores.ERROR}[!] {error}{Colores.FIN}")
