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
FLAGS_NMAP_RAPIDO    = "-n -Pn -T4 -p-"     # Descubrimiento rápido de todos los puertos
FLAGS_NMAP_SIGILOSO  = "-n -Pn -sS -p-"     # Descubrimiento sigiloso SYN de todos los puertos
FLAGS_NMAP_VERSIONES = "-n -Pn -sV -sC -O"  # Detección de versiones, scripts y SO

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

TIMEOUT_HTTP             = 10   # Peticiones HTTP
TIMEOUT_COMANDO          = 30   # Subprocesos genéricos (nmap scripts, etc.)
TIMEOUT_WHATWEB          = 40   # Límite de proceso para whatweb
WHATWEB_AGRESIVIDAD      = 1    # 1=pasivo, 3=agresivo (más peticiones, más lento)
WHATWEB_OPEN_TIMEOUT     = 8    # --open-timeout: tiempo máximo de conexión por petición
WHATWEB_READ_TIMEOUT     = 15   # --read-timeout: tiempo máximo de lectura por petición


# =============================================================================
# FASE 3 — Búsqueda de vulnerabilidades conocidas (searchsploit)
# =============================================================================

MAX_TERMINOS_SEARCHSPLOIT = 8
MAX_PALABRAS_VERSION      = 2    # Palabras del string de versión usadas en la búsqueda
SEVERIDAD_DEFECTO         = "media"
OWASP_CATEGORIA_DEFECTO   = ("A03:2025", "Software Supply Chain Failures")

MAPEO_OWASP = {
    # A01:2025 — Broken Access Control
    "lfi"                : ("A01:2025", "Broken Access Control - Local File Inclusion"),
    "local file"         : ("A01:2025", "Broken Access Control - Local File Inclusion"),
    "rfi"                : ("A01:2025", "Broken Access Control - Remote File Inclusion"),
    "remote file"        : ("A01:2025", "Broken Access Control - Remote File Inclusion"),
    "path traversal"     : ("A01:2025", "Broken Access Control - Path Traversal"),
    "directory traversal": ("A01:2025", "Broken Access Control - Path Traversal"),
    "csrf"               : ("A01:2025", "Broken Access Control - CSRF"),
    "privilege"          : ("A01:2025", "Broken Access Control - Privilege Escalation"),
    "ssrf"               : ("A01:2025", "Broken Access Control - SSRF"),
    # A02:2025 — Security Misconfiguration (era A05:2021)
    "information"        : ("A02:2025", "Security Misconfiguration - Info Disclosure"),
    "disclosure"         : ("A02:2025", "Security Misconfiguration - Info Disclosure"),
    # A03:2025 — Software Supply Chain Failures (nueva; absorbe A06:2021)
    "buffer overflow"    : ("A03:2025", "Software Supply Chain Failures"),
    "overflow"           : ("A03:2025", "Software Supply Chain Failures"),
    # A04:2025 — Cryptographic Failures (era A02:2021)
    "ssl"                : ("A04:2025", "Cryptographic Failures"),
    "tls"                : ("A04:2025", "Cryptographic Failures"),
    "weak cipher"        : ("A04:2025", "Cryptographic Failures"),
    "weak encryption"    : ("A04:2025", "Cryptographic Failures"),
    "certificate"        : ("A04:2025", "Cryptographic Failures"),
    "openssl"            : ("A04:2025", "Cryptographic Failures"),
    # A05:2025 — Injection (era A03:2021)
    "rce"                : ("A05:2025", "Injection / Remote Code Execution"),
    "remote code"        : ("A05:2025", "Injection / Remote Code Execution"),
    "sql injection"      : ("A05:2025", "Injection - SQL Injection"),
    "sqli"               : ("A05:2025", "Injection - SQL Injection"),
    "xss"                : ("A05:2025", "Injection - Cross-Site Scripting"),
    "cross-site"         : ("A05:2025", "Injection - Cross-Site Scripting"),
    # A06:2025 — Insecure Design (era A04:2021)
    "file upload"        : ("A06:2025", "Insecure Design - Unrestricted File Upload"),
    # A07:2025 — Authentication Failures (era A07:2021, renombrada)
    "authentication"     : ("A07:2025", "Authentication Failures"),
    "bypass"             : ("A07:2025", "Authentication Failures"),
    # A08:2025 — Software and Data Integrity Failures (era A08:2021)
    "deserialization"    : ("A08:2025", "Software and Data Integrity Failures"),
    # A09:2025 — Logging & Alerting Failures (era A09:2021, renombrada)
    "log injection"      : ("A09:2025", "Logging & Alerting Failures"),
    "log forging"        : ("A09:2025", "Logging & Alerting Failures"),
    "audit"              : ("A09:2025", "Logging & Alerting Failures"),
    # A10:2025 — Mishandling of Exceptional Conditions (nueva)
    "exception"          : ("A10:2025", "Mishandling of Exceptional Conditions"),
    "error handling"     : ("A10:2025", "Mishandling of Exceptional Conditions"),
}

PALABRAS_CLAVE_SEVERIDAD = {
    "critica": ["remote code execution", "rce", "unauthenticated", "root"],
    "alta"   : ["sql injection", "privilege escalation", "buffer overflow", "lfi", "rfi"],
    "media"  : ["xss", "csrf", "information disclosure", "bypass"],
    "baja"   : ["information", "version", "disclosure"],
}


# =============================================================================
# MÓDULO OPCIONAL — Fuzzing web (ffuf)
# =============================================================================

TIMEOUT_FFUF          = 600    # Timeout global del proceso ffuf (10 minutos)
FFUF_HILOS            = 50
FFUF_TIMEOUT_PETICION = 5      # Timeout por petición individual
FFUF_CODIGOS_ESTADO   = "200,301,302,403"
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
