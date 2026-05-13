# =============================================================================
# AuditX - configuracion.py
# =============================================================================
# Configuración global de la herramienta: rutas, timeouts, flags y colores.
# =============================================================================

import os

# --- Rutas base del proyecto ---
DIRECTORIO_BASE      = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_INFORMES  = os.path.join(DIRECTORIO_BASE, "informes")
DIRECTORIO_WORDLISTS = os.path.join(DIRECTORIO_BASE, "wordlists")

# --- Timeouts en segundos ---
TIMEOUT_NMAP    = 300   # 5 minutos para escaneo de puertos
TIMEOUT_HTTP    = 10    # Peticiones HTTP
TIMEOUT_SOCKET  = 5     # Banner grabbing por socket
TIMEOUT_COMANDO = 30    # Subprocesos genéricos (nmap scripts, whatweb, etc.)

# --- Flags de nmap ---
FLAGS_NMAP_DEFECTO  = "-n -Pn -sV -sC"
FLAGS_NMAP_SIGILOSO = "-n -Pn -sS -p-"

# --- Extensiones a buscar en fuzzing ---
EXTENSIONES_FUZZ = ".php,.html,.txt,.js,.bak"

# --- Herramientas externas requeridas y comando de instalación ---
HERRAMIENTAS_REQUERIDAS = {
    "nmap"        : "sudo apt install nmap -y",
    "curl"        : "sudo apt install curl -y",
    "whatweb"     : "sudo apt install whatweb -y",
    "ffuf"        : "sudo apt install ffuf -y",
    "searchsploit": "sudo apt install exploitdb -y",
}

# --- Pipeline de auditoría ---
TOTAL_FASES = 4

# --- Formato de consola ---
ANCHO_SEPARADOR      = 60
ANCHO_AYUDA          = 110
POSICION_MAX_AYUDA   = 40

# --- Puertos web de interés ---
PUERTOS_WEB = [80, 443, 8080, 8443, 8000, 8888]

# --- Mapa puerto → tipo de servicio ---
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


# --- Colores para la salida por consola (códigos ANSI) ---
class Colores:
    CABECERA    = '\033[95m'
    AZUL        = '\033[94m'
    CIAN        = '\033[96m'
    VERDE       = '\033[92m'
    ADVERTENCIA = '\033[93m'
    ERROR       = '\033[91m'
    FIN         = '\033[0m'
    NEGRITA     = '\033[1m'


# --- Banner de la herramienta ---
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
