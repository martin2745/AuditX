# AuditX

**Herramienta modular de auditoría de seguridad automatizada**

> Desarrollada como parte del Trabajo Fin de Máster en Ciberseguridad  
> Universidad Internacional Isabel I de Castilla — Curso 2025/26  
> Autor: Martín Gil Blanco

---

## Aviso Legal

Esta herramienta ha sido desarrollada con fines **exclusivamente académicos y de investigación**.  
Su uso está permitido **únicamente sobre sistemas propios o con autorización explícita por escrito**.  
El uso no autorizado sobre sistemas ajenos es ilegal y puede conllevar responsabilidad penal.

---

## Descripción

AuditX automatiza las fases de una auditoría de seguridad siguiendo las metodologías **PTES** (Penetration Testing Execution Standard) y **OWASP WSTG** (Web Security Testing Guide).

La herramienta orquesta de forma secuencial tres fases obligatorias y dos módulos opcionales, tomando como entrada mínima una **IP o hostname objetivo**.

---

## Arquitectura

```
AuditX/
│
├── main.py                          # Punto de entrada y orquestador del pipeline
├── configuracion.py                 # Configuración global: rutas, timeouts, constantes
│
├── descubrimiento.py                # Fase 1: Escaneo de puertos (nmap)
├── fingerprinting/                  # Fase 2: Identificación de tecnologías
│   ├── __init__.py                  #   Orquestador: despacha según tipo de servicio
│   ├── base.py                      #   Utilidades compartidas (socket, comandos)
│   ├── web.py                       #   HTTP/HTTPS: curl + whatweb
│   ├── ssh.py                       #   SSH: banner grabbing
│   ├── ftp.py                       #   FTP: acceso anónimo
│   ├── smb.py                       #   SMB: signing, shares
│   ├── mysql.py                     #   MySQL: acceso sin credenciales
│   └── rdp.py                       #   RDP: detección
├── busqueda_vulnerabilidades.py     # Fase 3: Búsqueda de CVEs (searchsploit)
│
├── enumeracion.py                   # Módulo opcional: Fuzzing web (ffuf) [--fuzz]
├── generador_informe.py             # Módulo opcional: Informe Markdown [--informe]
├── escaneo_red.py                   # Descubrimiento de hosts en red (nmap -sn)
│
├── wordlists/
│   └── default.txt                  # Wordlist curada por defecto
└── informes/                        # Informes generados (creado automáticamente)
```

### Flujo de ejecución

```
Arranque
    │
    ▼
Menú interactivo  ──o──  -t IP  ──o──  -n RED
    │
    ▼
┌─────────────────────────────────────────────┐
│  Fase 1 — descubrimiento.py                 │  nmap
│  Escaneo de puertos y detección de servicios│
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Fase 2 — fingerprinting/                   │  curl + whatweb
│  Identificación de tecnologías y versiones  │
└────────────────────┬────────────────────────┘
                     │
                     ├──► [--fuzz]  Módulo opcional: enumeracion.py  (ffuf)
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Fase 3 — busqueda_vulnerabilidades.py      │  searchsploit
│  Búsqueda de CVEs y clasificación OWASP     │
└────────────────────┬────────────────────────┘
                     │
                     └──► [--informe]  Módulo opcional: generador_informe.py
```

Para un mayor nivel de detalle se recomienda ver el [diagrama de flujo completo](docs/flujo_auditx.md).

---

## Requisitos

### Sistema operativo

- **Kali Linux** (recomendado) o cualquier distribución Debian/Ubuntu
- No compatible con Windows de forma nativa (usar WSL)

### Python

- Python 3.8 o superior
- Sin dependencias externas — solo biblioteca estándar

### Herramientas externas

Herramientas **obligatorias** (verificadas automáticamente al arrancar):

```bash
sudo apt install -y nmap curl whatweb exploitdb
```

Herramientas **opcionales** (solo necesarias si se usa `--fuzz`):

```bash
sudo apt install -y ffuf
```

Wordlists del sistema (recomendado):

```bash
sudo apt install -y seclists
```

---

## Instalación

```bash
git clone https://github.com/tu-usuario/AuditX.git
cd AuditX
```

No se requieren entornos virtuales ni dependencias Python adicionales.

---

## Uso rápido

```bash
# Menú interactivo
sudo python3 main.py

# Auditoría directa
sudo python3 main.py -t 192.168.1.10

# Con fuzzing web
sudo python3 main.py -t 192.168.1.10 --fuzz

# Con fuzzing e informe
sudo python3 main.py -t 192.168.1.10 --fuzz --informe

# Con wordlist propia e informe en ruta personalizada
sudo python3 main.py -t 192.168.1.10 --fuzz -w /usr/share/wordlists/dirb/common.txt --informe -o /tmp/informe.md
```

**Para una guía completa de uso consulta el [Manual de Usuario](manual_usuario.md)**

---

## Fases y módulos

| Tipo     | Módulo                         | Herramienta      | Descripción                                  |
|----------|--------------------------------|------------------|----------------------------------------------|
| Fase 1   | `descubrimiento.py`            | nmap             | Escaneo de puertos y detección de servicios  |
| Fase 2   | `fingerprinting/`              | curl, whatweb    | Identificación de tecnologías y versiones    |
| Fase 3   | `busqueda_vulnerabilidades.py` | searchsploit     | Búsqueda de CVEs y clasificación OWASP       |
| Opcional | `enumeracion.py`               | ffuf             | Fuzzing de directorios web (`--fuzz`)        |
| Opcional | `generador_informe.py`         | —                | Informe Markdown (`--informe`)               |
| Extra    | `escaneo_red.py`               | nmap -sn         | Ping sweep para descubrir hosts en red       |

---

## Informe generado

El informe (activado con `--informe`) se guarda en `informes/` con el nombre:

```
AuditX_Informe_<IP>_<YYYYMMDD_HHMMSS>.md
```

Estructura:

1. **Resumen Ejecutivo** — objetivo, fecha, nivel de riesgo, métricas
2. **Descubrimiento de Puertos y Servicios** — tabla de puertos, SO, metadatos HTTP
3. **Fingerprinting de Servicios** — servidor, CMS, tecnologías, cabeceras de seguridad
4. **Enumeración de Directorios** — rutas descubiertas (si se usó `--fuzz`)
5. **Clasificación OWASP Top 10 2025** — hallazgos agrupados por categoría con CVE
6. **Vulnerabilidades Identificadas** — fichas por exploit con CVE, severidad y categoría OWASP

---

## Referencias

- [OWASP Top 10 2025](https://owasp.org/Top10/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [Exploit-DB](https://www.exploit-db.com/)

---

## Contexto académico

Esta herramienta fue desarrollada como parte del TFM *"Evaluación de la seguridad en aplicaciones web mediante pruebas de penetración y análisis de vulnerabilidades"* del Máster en Ciberseguridad de la Universidad Internacional Isabel I de Castilla.
