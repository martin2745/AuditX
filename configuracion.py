# =============================================================================
# AuditX - configuracion.py
# =============================================================================
# Configuración global de la herramienta: rutas, timeouts, flags y colores.
# =============================================================================

import os

# =============================================================================
# GENERAL — Rutas, pipeline y formato de consola
# =============================================================================

DIRECTORIO_BASE      = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_INFORMES  = os.path.join(DIRECTORIO_BASE, "informes")
DIRECTORIO_WORDLISTS = os.path.join(DIRECTORIO_BASE, "wordlists")

TOTAL_FASES = 3

ANCHO_SEPARADOR    = 60
ANCHO_AYUDA        = 110
POSICION_MAX_AYUDA = 40

# --- Herramientas externas requeridas y comando de instalación ---
HERRAMIENTAS_REQUERIDAS = {
    "nmap"        : "sudo apt install nmap -y",
    "curl"        : "sudo apt install curl -y",
    "whatweb"     : "sudo apt install whatweb -y",
    "searchsploit": "sudo apt install exploitdb -y",
}

# --- Herramientas opcionales (solo necesarias si se activa el módulo) ---
HERRAMIENTAS_OPCIONALES_FUZZ = {
    "ffuf": "sudo apt install ffuf -y",
}


# =============================================================================
# FASE 1 — Descubrimiento de puertos y servicios (nmap)
# =============================================================================

TIMEOUT_NMAP        = 300    # 5 minutos para escaneo de puertos
TIMEOUT_SOCKET      = 5      # Banner grabbing por socket
FLAGS_NMAP_DEFECTO  = "-n -Pn -sV -sC"
FLAGS_NMAP_SIGILOSO = "-n -Pn -sS -p-"

PUERTOS_WEB = [80, 443, 8080, 8443, 8000, 8888]

MAPA_SERVICIOS = {
    21   : "ftp",
    22   : "ssh",
    23   : "telnet",
    25   : "smtp",
    53   : "dns",
    80   : "http",
    110  : "pop3",
    143  : "imap",
    443  : "https",
    445  : "smb",
    139  : "smb",
    1433 : "mssql",
    3306 : "mysql",
    3389 : "rdp",
    5432 : "postgresql",
    5900 : "vnc",
    6379 : "redis",
    8000 : "http",
    8080 : "http",
    8443 : "https",
    8888 : "http",
    27017: "mongodb",
}


# =============================================================================
# FASE 2 — Fingerprinting de servicios (whatweb, curl)
# =============================================================================

TIMEOUT_HTTP    = 10    # Peticiones HTTP
TIMEOUT_COMANDO = 30    # Subprocesos genéricos (nmap scripts, etc.)
TIMEOUT_WHATWEB = 60    # whatweb puede tardar más según el objetivo
WHATWEB_AGRESIVIDAD = 1 # 1=pasivo, 3=agresivo (más peticiones, más lento)


# =============================================================================
# FASE 3 — Búsqueda de vulnerabilidades conocidas (searchsploit)
# =============================================================================

MAX_TERMINOS_SEARCHSPLOIT = 8


# =============================================================================
# MÓDULO OPCIONAL — Fuzzing web (ffuf)
# =============================================================================

TIMEOUT_FFUF          = 600    # Timeout global del proceso ffuf (10 minutos)
FFUF_HILOS            = 50
FFUF_TIMEOUT_PETICION = 5      # Timeout por petición individual
FFUF_CODIGOS_ESTADO   = "200,301,302,403"
FFUF_ARCHIVO_SALIDA   = "/tmp/auditx_ffuf_salida.json"
WORDLIST_DEFECTO      = os.path.join(DIRECTORIO_WORDLISTS, "default.txt")
WORDLIST_SISTEMA      = "/usr/share/wordlists/dirb/common.txt"
EXTENSIONES_FUZZ      = ".php,.html,.txt,.js,.bak"


# =============================================================================
# CONSOLA — Colores ANSI y banner
# =============================================================================

class Colores:
    CABECERA    = '\033[95m'
    AZUL        = '\033[94m'
    CIAN        = '\033[96m'
    VERDE       = '\033[92m'
    ADVERTENCIA = '\033[93m'
    ERROR       = '\033[91m'
    FIN         = '\033[0m'
    NEGRITA     = '\033[1m'


BANNER = f"""
{Colores.CIAN}{Colores.NEGRITA}
  █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗  ██╗
 ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝╚██╗██╔╝
 ███████║██║   ██║██║  ██║██║   ██║    ╚███╔╝
 ██╔══██║██║   ██║██║  ██║██║   ██║    ██╔██╗
 ██║  ██║╚██████╔╝██████╔╝██║   ██║   ██╔╝ ██╗
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝
{Colores.FIN}
{Colores.VERDE}  [ Herramienta modular de auditoría de hosts y redes ]{Colores.FIN}
{Colores.ADVERTENCIA}  [ Uso exclusivo en entornos controlados y con autorización ]{Colores.FIN}
  Autor  : Martín Gil Blanco
  TFM    : Máster en Ciberseguridad - Universidad Isabel I
  Versión: 1.0.0
"""
