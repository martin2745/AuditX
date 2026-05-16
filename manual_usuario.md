# AuditX — Manual de Usuario

> **Versión:** 1.0.0  
> **Autor:** Martín Gil Blanco  
> **TFM:** Máster en Ciberseguridad — Universidad Internacional Isabel I de Castilla

---

## Índice

1. [Introducción](#1-introducción)
2. [Requisitos previos](#2-requisitos-previos)
   - 2.1 [Sistema operativo](#21-sistema-operativo)
   - 2.2 [Python](#22-python)
   - 2.3 [Herramientas externas](#23-herramientas-externas)
3. [Instalación](#3-instalación)
4. [Estructura del proyecto](#4-estructura-del-proyecto)
5. [Modos de ejecución](#5-modos-de-ejecución)
   - 5.1 [Menú interactivo](#51-menú-interactivo)
   - 5.2 [Auditoría directa por CLI](#52-auditoría-directa-por-cli)
   - 5.3 [Escaneo de red por CLI](#53-escaneo-de-red-por-cli)
6. [Referencia completa de opciones](#6-referencia-completa-de-opciones)
7. [Fases de auditoría](#7-fases-de-auditoría)
   - 7.1 [Fase 1 — Descubrimiento de puertos](#71-fase-1--descubrimiento-de-puertos)
   - 7.2 [Fase 2 — Fingerprinting de tecnologías](#72-fase-2--fingerprinting-de-tecnologías)
   - 7.3 [Fase 3 — Búsqueda de vulnerabilidades](#73-fase-3--búsqueda-de-vulnerabilidades)
8. [Módulos opcionales](#8-módulos-opcionales)
   - 8.1 [Fuzzing web (`--fuzz`)](#81-fuzzing-web---fuzz)
   - 8.2 [Informe Markdown (`--informe`)](#82-informe-markdown---informe)
9. [Gestión de wordlists](#9-gestión-de-wordlists)
10. [El informe de auditoría](#10-el-informe-de-auditoría)
11. [Casos de uso prácticos](#11-casos-de-uso-prácticos)
    - 11.1 [Auditoría rápida de reconocimiento](#111-auditoría-rápida-de-reconocimiento)
    - 11.2 [Auditoría estándar con informe](#112-auditoría-estándar-con-informe)
    - 11.3 [Auditoría completa con fuzzing e informe](#113-auditoría-completa-con-fuzzing-e-informe)
    - 11.4 [Auditoría sigilosa](#114-auditoría-sigilosa)
    - 11.5 [Fuzzing con wordlist personalizada](#115-fuzzing-con-wordlist-personalizada)
    - 11.6 [Fuzzing con timeout reducido](#116-fuzzing-con-timeout-reducido)
    - 11.7 [Auditar múltiples máquinas en sesión](#117-auditar-múltiples-máquinas-en-sesión)
    - 11.8 [Diagnóstico con modo verbose](#118-diagnóstico-con-modo-verbose)
    - 11.9 [Informe en ruta personalizada](#119-informe-en-ruta-personalizada)
    - 11.10 [Auditoría sin búsqueda de CVEs](#1110-auditoría-sin-búsqueda-de-cves)
12. [Solución de problemas frecuentes](#12-solución-de-problemas-frecuentes)
13. [Aviso legal](#13-aviso-legal)

---

## 1. Introducción

**AuditX** es una herramienta de auditoría de seguridad modular que automatiza tres fases obligatorias de análisis sobre un objetivo, más dos módulos opcionales que se activan bajo demanda:

**Fases obligatorias** (se ejecutan siempre):

1. **Descubrimiento** — escaneo de puertos y detección de servicios con `nmap`.
2. **Fingerprinting** — identificación de tecnologías web (servidor, CMS, versiones) con `curl` y `whatweb`.
3. **Búsqueda de vulnerabilidades** — búsqueda de CVEs en Exploit-DB con `searchsploit`, clasificados según **OWASP Top 10 2021**.

**Módulos opcionales** (se activan con sus flags):

- **`--fuzz`** — fuzzing de directorios y archivos web con `ffuf`. Solo se ejecuta si el objetivo tiene puertos web abiertos.
- **`--informe`** — generación de un informe en formato Markdown con índice navegable, tabla de riesgo y clasificación OWASP.

La herramienta puede arrancarse sin argumentos mostrando un **menú interactivo**, o bien recibir el objetivo directamente por línea de comandos para integrarla en flujos automatizados.

---

## 2. Requisitos previos

### 2.1 Sistema operativo

- **Kali Linux** (recomendado): todas las herramientas necesarias están disponibles en sus repositorios.
- Cualquier distribución Debian/Ubuntu con acceso a `apt`.
- No es compatible con Windows de forma nativa (se requiere WSL si se usa en Windows).

### 2.2 Python

```bash
python3 --version
```

Se requiere **Python 3.8 o superior**. AuditX no usa ninguna librería externa: solo la biblioteca estándar de Python.

### 2.3 Herramientas externas

AuditX verifica automáticamente al arrancar que las herramientas necesarias estén instaladas e indica el comando exacto para instalar las que falten.

**Herramientas obligatorias** (requeridas siempre):

| Herramienta    | Uso en la herramienta                           | Instalación                       |
|----------------|-------------------------------------------------|-----------------------------------|
| `nmap`         | Escaneo de puertos, versiones y detección de SO | `sudo apt install nmap -y`        |
| `curl`         | Obtención de cabeceras HTTP                     | `sudo apt install curl -y`        |
| `whatweb`      | Identificación de tecnologías web               | `sudo apt install whatweb -y`     |
| `searchsploit` | Búsqueda de CVEs en Exploit-DB                  | `sudo apt install exploitdb -y`   |

```bash
sudo apt update
sudo apt install -y nmap curl whatweb exploitdb
```

**Herramientas opcionales** (solo necesarias si se usa `--fuzz`):

| Herramienta | Uso                               | Instalación                   |
|-------------|-----------------------------------|-------------------------------|
| `ffuf`      | Fuzzing de directorios y archivos | `sudo apt install ffuf -y`    |

```bash
sudo apt install -y ffuf
```

**Wordlists del sistema** (recomendado para ampliar la cobertura del fuzzing):

```bash
sudo apt install -y seclists
```

---

## 3. Instalación

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/AuditX.git
cd AuditX
```

No es necesario instalar dependencias Python ni crear entornos virtuales.

Para verificar que las herramientas obligatorias funcionan correctamente antes de lanzar una auditoría real:

```bash
sudo python3 main.py -t 127.0.0.1 --omitir-vuln
```

Este comando ejecuta las fases 1 y 2 contra localhost (sin búsqueda de CVEs), lo que permite comprobar que `nmap`, `curl` y `whatweb` están operativos.

---

## 4. Estructura del proyecto

```
AuditX/
│
├── main.py                          # Punto de entrada y orquestador del pipeline
├── configuracion.py                 # Configuración global: rutas, timeouts, constantes
│
├── descubrimiento.py                # Fase 1: escaneo de puertos con nmap
├── fingerprinting/                  # Fase 2: identificación de tecnologías
│   ├── __init__.py                  #   Orquestador: despacha según tipo de servicio
│   ├── base.py                      #   Utilidades compartidas (socket, comandos)
│   ├── web.py                       #   HTTP/HTTPS: curl + whatweb
│   ├── ssh.py                       #   SSH: banner grabbing
│   ├── ftp.py                       #   FTP: acceso anónimo
│   ├── smb.py                       #   SMB: signing, shares
│   ├── mysql.py                     #   MySQL: acceso sin credenciales
│   └── rdp.py                       #   RDP: detección
├── busqueda_vulnerabilidades.py     # Fase 3: búsqueda de CVEs con searchsploit
│
├── enumeracion.py                   # Módulo opcional: fuzzing web (--fuzz)
├── generador_informe.py             # Módulo opcional: informe Markdown (--informe)
├── escaneo_red.py                   # Descubrimiento de hosts en red (nmap -sn)
│
├── wordlists/
│   └── default.txt                  # Wordlist curada por defecto
└── informes/                        # Directorio creado automáticamente al generar informes
```

---

## 5. Modos de ejecución

AuditX ofrece tres formas de arrancar, todas equivalentes en capacidad pero adaptadas a distintos flujos de trabajo.

---

### 5.1 Menú interactivo

**Cuándo usarlo:** cuando no sabes de antemano qué máquina quieres auditar, o quieres explorar primero la red.

```bash
sudo python3 main.py
```

Al ejecutar sin argumentos aparece el menú principal:

```
============================================================
  ¿Qué deseas hacer?
============================================================
  [1]  Escanear la red y elegir objetivo
  [2]  Auditar una máquina directamente
  [q]  Salir
============================================================

  Opción:
```

#### Opción 1 — Escanear la red

Al elegir `1`, la herramienta pide el rango de red:

```
  Introduce el rango de red (ej: 192.168.100.0/24): 192.168.100.0/24
```

Realiza un **ping sweep** (`nmap -sn`) y muestra la tabla de hosts activos:

```
[+] Hosts activos descubiertos: 4

    #    IP                 Nombre host               MAC                  Fabricante
    ---- ------------------ ------------------------- -------------------- ---------------
    1    192.168.100.1      router.local              AA:BB:CC:11:22:33    Cisco Systems
    2    192.168.100.5      -                         DD:EE:FF:44:55:66    VMware
    3    192.168.100.6      metasploitable             -                    -
    4    192.168.100.7      kali                      -                    -

  Selecciona el numero del host a auditar (1-4) o 'q' para salir:
```

Se introduce el número del host deseado y comienza la auditoría. Al terminar, pregunta si se quiere auditar otro:

```
  ¿Auditar otro host? [s/N]:
```

- Responder `s` vuelve a mostrar la tabla para elegir otro host.
- Responder `N` o pulsar Enter termina la sesión.

#### Opción 2 — Auditar máquina directamente

Al elegir `2`, pide la IP o hostname:

```
  Introduce la IP o hostname del objetivo: 192.168.100.6
```

Lanza las tres fases obligatorias y termina al finalizar (sin bucle).

---

### 5.2 Auditoría directa por CLI

**Cuándo usarlo:** cuando ya conoces el objetivo y quieres lanzar la auditoría directamente, o para integrarlo en scripts.

```bash
sudo python3 main.py -t <IP_O_HOSTNAME>
```

Ejemplo:

```bash
sudo python3 main.py -t 192.168.100.6
```

La herramienta ejecuta las tres fases obligatorias. Al terminar, **no pregunta si continuar**: finaliza la ejecución. Se puede combinar con cualquiera de las opciones descritas en la sección 6.

---

### 5.3 Escaneo de red por CLI

**Cuándo usarlo:** cuando quieres pasar directamente al modo red sin pasar por el menú, o para integrarlo en scripts.

```bash
sudo python3 main.py -n <RANGO_CIDR>
```

Ejemplo:

```bash
sudo python3 main.py -n 192.168.100.0/24
```

Equivale a elegir la opción 1 del menú interactivo: descubre hosts, muestra la tabla, permite elegir objetivo y auditar en bucle.

---

## 6. Referencia completa de opciones

```
uso: python3 main.py [-t OBJETIVO | -n RED] [opciones]
```

### Objetivo (mutuamente excluyentes)

| Opción | Descripción |
|--------|-------------|
| `-t OBJETIVO`, `--objetivo OBJETIVO` | IP o hostname de la máquina a auditar directamente. |
| `-n RED`, `--red RED` | Rango de red en notación CIDR. Activa el modo de escaneo de red con selección interactiva de objetivo. |

Si no se indica ninguno de los dos, se muestra el menú interactivo.

---

### Opciones de escaneo

| Opción | Descripción |
|--------|-------------|
| `--sigiloso` | Usa escaneo TCP SYN (`nmap -sS -p-`) en lugar del escaneo estándar. Más lento pero menos detectable. **Requiere sudo.** |
| `--omitir-vuln` | Omite la Fase 3 (búsqueda de CVEs con searchsploit). Útil cuando solo interesa el reconocimiento. |

---

### Módulos opcionales

| Opción | Descripción |
|--------|-------------|
| `--fuzz` | Activa el módulo de fuzzing de directorios web con `ffuf`. Solo se ejecuta si el objetivo tiene puertos web detectados. Requiere `ffuf` instalado. |
| `--informe` | Genera un informe Markdown al finalizar la auditoría. Por defecto, **no se genera informe**. |

---

### Opciones del módulo de fuzzing (requieren `--fuzz`)

| Opción | Descripción |
|--------|-------------|
| `-w RUTA`, `--wordlist RUTA` | Ruta a una wordlist personalizada para `ffuf`. Si no se indica, usa `wordlists/default.txt`. Si ese fichero no existe, usa `/usr/share/wordlists/dirb/common.txt` como fallback. |
| `--timeout-fuzz SEGUNDOS` | Tiempo máximo en segundos para `ffuf` por URL. Por defecto: **600 segundos** (10 minutos). |

---

### Opciones del módulo de informe (requieren `--informe`)

| Opción | Descripción |
|--------|-------------|
| `-o RUTA`, `--salida RUTA` | Ruta y nombre de fichero personalizados para el informe. Por defecto los informes se guardan en `informes/AuditX_Informe_<IP>_<timestamp>.md`. |

---

### Opciones de salida

| Opción | Descripción |
|--------|-------------|
| `-v`, `--verbose` | Muestra la salida raw (sin procesar) de nmap, curl/whatweb y ffuf directamente en la terminal. Útil para depuración. |

---

## 7. Fases de auditoría

### 7.1 Fase 1 — Descubrimiento de puertos

**Módulo:** `descubrimiento.py`  
**Herramienta:** `nmap`

Esta fase realiza dos escaneos consecutivos:

**Paso 1 — Escaneo de todos los puertos TCP**

En modo normal:
```
nmap -n -Pn -sV -sC <objetivo>
```

En modo sigiloso (`--sigiloso`):
```
nmap -n -Pn -sS -p- <objetivo>
```

**Paso 2 — Análisis detallado de servicios**

Sobre los puertos abiertos encontrados:
- Versión exacta de cada servicio (`-sV`)
- Scripts NSE por defecto (`-sC`): título de páginas web, metadatos HTTP, etc.
- Detección de sistema operativo

**Resultado:** lista de puertos con protocolo, estado, servicio, versión y si son accesibles por web (puertos 80, 443, 8080, 8443, 8000, 8888).

---

### 7.2 Fase 2 — Fingerprinting de tecnologías

**Módulo:** `fingerprinting/`  
**Herramientas:** `curl`, `whatweb` (web); sockets directos para SSH, FTP, SMB, MySQL, RDP

El módulo de fingerprinting analiza cada servicio detectado en la Fase 1 con la técnica adecuada a su tipo:

#### Servicios web (HTTP/HTTPS)

**Análisis de cabeceras con curl:**
```
curl -s -I --max-time 10 --insecure <url>
```

Extrae:
- Servidor web y versión (cabecera `Server`)
- CMS por cabeceras específicas
- Tecnología backend (cabecera `X-Powered-By`)
- Presencia o ausencia de las seis cabeceras de seguridad recomendadas:
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `X-XSS-Protection`
  - `Referrer-Policy`

**Identificación de tecnologías con whatweb** (modo pasivo, nivel de agresividad 1):
```
whatweb --no-errors -a 1 <url>
```

Detecta frameworks, librerías JavaScript, versiones de CMS, plataformas, etc.

> El nivel de agresividad 1 (pasivo) realiza una única petición HTTP por URL, lo que evita falsos positivos y timeouts en objetivos con detección de escaneos.

#### Otros servicios

| Servicio | Técnica |
|----------|---------|
| SSH      | Banner grabbing por socket |
| FTP      | Detección de acceso anónimo |
| SMB      | Detección de message signing deshabilitado |
| MySQL    | Detección de acceso sin credenciales |
| RDP      | Detección de presencia |

**Resultado:** servidor web, CMS con versión, lista de tecnologías, estado de cabeceras de seguridad HTTP, y advertencias específicas por servicio (FTP anónimo, SMB signing, etc.).

---

### 7.3 Fase 3 — Búsqueda de vulnerabilidades

**Módulo:** `busqueda_vulnerabilidades.py`  
**Herramienta:** `searchsploit`

Construye términos de búsqueda a partir de los resultados del fingerprinting, priorizando:

1. CMS con versión (ej. `SPIP 4.2.1`) — mayor precisión
2. Servidor web con versión (ej. `Apache 2.4.52`)
3. Otras tecnologías con número de versión detectadas por whatweb

Ejecuta hasta **8 búsquedas** para cubrir todas las tecnologías relevantes:

```
searchsploit --json <termino>
```

Por cada exploit encontrado:
- Extrae título, ruta en Exploit-DB, tipo y fecha
- Extrae el **CVE** asociado (del campo `Codes` de searchsploit o por expresión regular en el título)
- **Clasifica la severidad** según palabras clave en el título:
  - **CRITICO:** `remote code execution`, `rce`, `unauthenticated`, `root`
  - **ALTO:** `sql injection`, `privilege escalation`, `buffer overflow`, `lfi`, `rfi`
  - **MEDIO:** `xss`, `csrf`, `information disclosure`, `bypass`
  - **BAJO:** `information`, `version`, `disclosure`
- **Mapea a OWASP Top 10 2021** (A01–A10)

Los resultados se muestran agrupados por categoría OWASP ordenadas de A01 a A10, con el CVE de cada vulnerabilidad. Esta misma estructura se traslada al informe si se genera con `--informe`.

**Resultado:** vulnerabilidades clasificadas por categoría OWASP con CVE, severidad y términos de búsqueda utilizados.

---

## 8. Módulos opcionales

### 8.1 Fuzzing web (`--fuzz`)

**Módulo:** `enumeracion.py`  
**Herramienta:** `ffuf`  
**Activación:** flag `--fuzz`

El módulo de fuzzing realiza descubrimiento de directorios y archivos ocultos sobre los puertos web detectados en la Fase 1. **Si no se detectan puertos web abiertos, el módulo se omite automáticamente** con un aviso.

**Comando ejecutado:**
```
ffuf -u <url>/FUZZ -w <wordlist> -e .php,.html,.txt,.js,.bak
     -ic -o /tmp/auditx_ffuf_salida.json -of json
     -mc 200,301,302,403 -t 50 -timeout 5
```

Parámetros relevantes:
- `-e .php,.html,.txt,.js,.bak` — prueba cada entrada con estas cinco extensiones
- `-mc 200,301,302,403` — filtra solo respuestas con estos códigos HTTP
- `-t 50` — 50 hilos en paralelo
- `-timeout 5` — máximo 5 segundos por petición individual

La salida nativa de ffuf (banner y barra de progreso) se suprime para mantener limpia la consola de AuditX. Al finalizar se muestra un resumen con todas las rutas descubiertas, marcando con `*` las clasificadas como de interés:

```
        Rutas descubiertas:
          [200] http://192.168.100.6/index.php (1234 bytes)
          [301] http://192.168.100.6/admin (0 bytes) *
          [403] http://192.168.100.6/.git (0 bytes) *
          [200] http://192.168.100.6/config.php (512 bytes) *
```

Los hallazgos marcados con `*` contienen patrones sensibles: `admin`, `config`, `backup`, `.git`, `.env`, `login`, `panel`, `phpmyadmin`, `wp-admin`, `db`, `secret`, `token`, etc.

**Activación:**

```bash
sudo python3 main.py -t 192.168.100.6 --fuzz
```

---

### 8.2 Informe Markdown (`--informe`)

**Módulo:** `generador_informe.py`  
**Activación:** flag `--informe`

Por defecto AuditX **no genera ningún fichero**: muestra los resultados en pantalla y termina. Al activar `--informe` se genera un documento Markdown completo con toda la información de la auditoría.

El informe se guarda en `informes/` con el nombre:

```
AuditX_Informe_<IP_con_guiones>_<YYYYMMDD_HHMMSS>.md
```

Ejemplo:
```
informes/AuditX_Informe_192_168_100_6_20260507_213045.md
```

Se puede especificar una ruta alternativa con `-o`:

```bash
sudo python3 main.py -t 192.168.100.6 --informe -o /home/kali/auditorias/cliente_x.md
```

La estructura del informe se detalla en la [sección 10](#10-el-informe-de-auditoría).

---

## 9. Gestión de wordlists

La wordlist solo se usa cuando se activa `--fuzz`. La herramienta resuelve qué wordlist usar siguiendo este orden de prioridad:

```
1. Wordlist especificada con -w  (si se indicó y el fichero existe)
        |
        v
2. wordlists/default.txt         (wordlist curada incluida en el proyecto)
        |
        v
3. /usr/share/wordlists/dirb/common.txt  (fallback del sistema)
        |
        v
4. Error: no se encontró wordlist → fuzzing omitido
```

### Wordlist por defecto (`wordlists/default.txt`)

Incluida en el repositorio. Contiene rutas web comunes cuidadosamente seleccionadas: paneles de administración, ficheros de configuración, directorios sensibles, rutas de CMS populares, etc.

**Ventaja:** completa el fuzzing en pocos segundos.  
**Límite:** al ser pequeña, puede no descubrir rutas poco comunes.

### Wordlists recomendadas según el objetivo

| Situación | Wordlist recomendada | Tamaño aprox. |
|-----------|---------------------|---------------|
| Reconocimiento rápido | `wordlists/default.txt` (por defecto) | ~100 entradas |
| Auditoría general | `/usr/share/wordlists/dirb/common.txt` | ~4.600 entradas |
| Auditoría exhaustiva | `/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt` | ~87.000 entradas |
| Auditoría máxima cobertura | `/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` | ~220.000 entradas |

> Con la wordlist `medium` y las 5 extensiones configuradas se generan más de un millón de peticiones.
> Se recomienda aumentar `--timeout-fuzz` o disponer de buena conectividad con el objetivo.

### Especificar una wordlist por CLI

```bash
sudo python3 main.py -t 192.168.100.6 --fuzz -w /usr/share/wordlists/dirb/common.txt
```

Si la ruta indicada no existe, la herramienta avisa y cae al siguiente nivel de prioridad automáticamente.

---

## 10. El informe de auditoría

El informe (activado con `--informe`) es un documento Markdown con índice navegable. Su estructura varía ligeramente según si se detectaron hallazgos OWASP clasificables:

### Estructura del informe

```
# Informe de Auditoria de Seguridad de <IP>

## Indice
1. Resumen Ejecutivo
2. Descubrimiento de Puertos y Servicios
3. Fingerprinting de Servicios
4. Enumeracion de Directorios y Archivos
5. Clasificacion OWASP Top 10 2021        ← solo si hay vulnerabilidades clasificadas
6. Vulnerabilidades Identificadas
```

> Si no hay vulnerabilidades clasificadas en OWASP, la sección 5 es directamente "Vulnerabilidades Identificadas".

### Contenido de cada sección

**1. Resumen Ejecutivo**  
Tabla con objetivo, fecha de análisis, sistema operativo, puertos abiertos, tecnologías detectadas, vulnerabilidades encontradas y nivel de riesgo global (CRITICO / ALTO / MEDIO). Incluye distribución de vulnerabilidades por severidad (Crítica, Alta, Media, Baja).

**2. Descubrimiento de Puertos y Servicios**  
Sistema operativo detectado. Tabla con todos los puertos abiertos: protocolo, estado, servicio, versión y si son accesibles por web. Metadatos HTTP (título de la web, servidor, generador) si fueron detectados por nmap.

**3. Fingerprinting de Servicios**  
Tabla de servicios analizados con detalles (versión, banner, URL). Advertencias destacadas si se detectó FTP anónimo o SMB signing deshabilitado. Lista de tecnologías identificadas. Para servicios web: servidor, CMS detectado y tabla de cabeceras de seguridad HTTP marcadas como `[PRESENTE]` o `[AUSENTE]`.

**4. Enumeración de Directorios y Archivos**  
Wordlist utilizada, total de rutas analizadas y tabla de recursos de interés con código HTTP y tamaño de respuesta. Si no se ejecutó `--fuzz`, la sección indica que no se realizó enumeración.

**5. Clasificación OWASP Top 10 2021** *(si hay datos)*  
Agrupación de todas las vulnerabilidades por su categoría OWASP (A01–A10), ordenadas de A01 a A10. Para cada categoría: número de hallazgos, CVE y título de cada vulnerabilidad.

**6. Vulnerabilidades Identificadas**  
Una ficha por cada vulnerabilidad ordenada por código OWASP (A01→A10). Cada ficha incluye: CVE, severidad, término de búsqueda usado, ruta en Exploit-DB, tipo, fecha y categoría OWASP.

### Visualización del informe

El informe es Markdown estándar compatible con GitHub y con cualquier editor que lo soporte:

```bash
# Abrir en VS Code con vista previa
code informes/AuditX_Informe_*.md

# Ver en terminal con un visualizador Markdown
glow informes/AuditX_Informe_*.md       # si tienes glow instalado

# Convertir a HTML con pandoc
pandoc informes/AuditX_Informe_*.md -o informe.html
```

---

## 11. Casos de uso prácticos

### 11.1 Auditoría rápida de reconocimiento

**Objetivo:** obtener una visión rápida del objetivo sin búsqueda de CVEs ni informe.

```bash
sudo python3 main.py -t 192.168.100.6 --omitir-vuln
```

Ejecuta solo las fases 1 y 2. Termina en 1-3 minutos. Ideal para una primera exploración.

---

### 11.2 Auditoría estándar con informe

**Objetivo:** ejecutar las tres fases y guardar los resultados en un informe.

```bash
sudo python3 main.py -t 192.168.100.6 --informe
```

Ejecuta las tres fases obligatorias y genera el informe en `informes/`.

---

### 11.3 Auditoría completa con fuzzing e informe

**Objetivo:** auditoría completa incluyendo descubrimiento de rutas web.

```bash
sudo python3 main.py -t 192.168.100.6 --fuzz --informe
```

Ejecuta las tres fases obligatorias más el módulo de fuzzing, y genera el informe al final.

---

### 11.4 Auditoría sigilosa

**Objetivo:** reducir la huella del escaneo de puertos usando TCP SYN.

```bash
sudo python3 main.py -t 192.168.100.6 --sigiloso
```

El escaneo sigiloso usa `nmap -sS -p-` en la primera fase (sin completar el three-way handshake). Requiere ejecutar con `sudo`. Es más lento que el modo estándar porque escanea todos los puertos sin el flag `-T4`.

Con fuzzing e informe:

```bash
sudo python3 main.py -t 192.168.100.6 --sigiloso --fuzz --informe
```

---

### 11.5 Fuzzing con wordlist personalizada

**Objetivo:** usar una wordlist más exhaustiva para descubrir más rutas.

```bash
# Wordlist mediana de dirb (~4.600 entradas)
sudo python3 main.py -t 192.168.100.6 --fuzz -w /usr/share/wordlists/dirb/common.txt

# Wordlist grande de seclists (~87.000 entradas)
sudo python3 main.py -t 192.168.100.6 --fuzz \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt

# Wordlist propia
sudo python3 main.py -t 192.168.100.6 --fuzz -w /home/kali/mis-wordlists/mi_lista.txt
```

---

### 11.6 Fuzzing con timeout reducido

**Objetivo:** evitar que ffuf se quede bloqueado en redes lentas o máquinas con alta latencia.

```bash
# Limitar ffuf a 2 minutos
sudo python3 main.py -t 192.168.100.6 --fuzz --timeout-fuzz 120

# Combinado con wordlist propia
sudo python3 main.py -t 192.168.100.6 --fuzz \
  -w /usr/share/wordlists/dirb/common.txt \
  --timeout-fuzz 180
```

Si ffuf supera el timeout configurado, el módulo de fuzzing se cancela con un aviso y la auditoría continúa con la Fase 3.

---

### 11.7 Auditar múltiples máquinas en sesión

**Objetivo:** auditar varias máquinas de una misma red sin relanzar la herramienta.

```bash
sudo python3 main.py -n 192.168.100.0/24
```

O desde el menú interactivo:

```bash
sudo python3 main.py
# Elegir opción 1
# Introducir: 192.168.100.0/24
# Seleccionar host 1 → auditar
# ¿Auditar otro host? → s
# Seleccionar host 2 → auditar
# ¿Auditar otro host? → N → fin
```

Cada auditoría genera su propio informe en `informes/` (si se usa `--informe`) con timestamp independiente.

---

### 11.8 Diagnóstico con modo verbose

**Objetivo:** ver exactamente qué están devolviendo las herramientas externas para depurar un problema.

```bash
sudo python3 main.py -t 192.168.100.6 -v
```

Con `-v` activado, después de cada fase se imprime la salida raw completa de la herramienta correspondiente:

- `[RAW - nmap]` — salida completa del escaneo nmap
- `[RAW - fingerprinting]` — respuesta de cabeceras curl y salida de whatweb
- `[RAW - ffuf]` — salida completa de ffuf (si se usó `--fuzz`)

Útil para entender por qué no se detectó un CMS o por qué nmap no encontró puertos.

---

### 11.9 Informe en ruta personalizada

```bash
sudo python3 main.py -t 192.168.100.6 --informe -o /home/kali/auditorias/cliente_x.md
```

---

### 11.10 Auditoría sin búsqueda de CVEs

**Objetivo:** solo reconocimiento y fingerprinting, sin consultar Exploit-DB.

```bash
sudo python3 main.py -t 192.168.100.6 --omitir-vuln
```

Útil en entornos donde `searchsploit` no está disponible o cuando se quiere una auditoría rápida de reconocimiento.

---

## 12. Solución de problemas frecuentes

### La herramienta indica que falta una herramienta

```
[!] Herramientas no encontradas:
    x nmap  ->  sudo apt install nmap -y
```

Instala la herramienta indicada y vuelve a ejecutar:

```bash
sudo apt install nmap -y
```

Si el error es sobre `ffuf` y no vas a usar `--fuzz`, puedes ignorarlo: `ffuf` solo se verifica cuando se pasa ese flag.

---

### Fase 1 no encuentra puertos abiertos

Causas posibles:
- El objetivo no está activo o no es accesible desde tu máquina.
- Un firewall está bloqueando los paquetes.
- La herramienta se ejecutó sin `sudo` y nmap no tiene permisos suficientes.

Verificación:

```bash
# Comprobar conectividad básica
ping 192.168.100.6

# Probar nmap manualmente
sudo nmap -n -Pn -T4 -p 80,443,22 192.168.100.6
```

---

### Fase 2 — whatweb tarda demasiado o no responde

AuditX usa whatweb en modo pasivo (agresividad 1) con un timeout de 60 segundos. Si aun así se producen timeouts, puede deberse a alta latencia con el objetivo.

Verificación manual:

```bash
whatweb --no-errors -a 1 http://192.168.100.6
```

---

### El módulo de fuzzing no se ejecuta aunque está activo

Si la Fase 1 no detecta puertos web (80, 443, 8080, 8443, 8000, 8888), el módulo de fuzzing se omite automáticamente con el mensaje:

```
[!] No se detectaron puertos web abiertos. Fuzzing omitido.
```

Comprueba que el objetivo sirve tráfico web y que los puertos están dentro del rango detectado.

---

### El módulo de fuzzing supera el timeout

```
[!] ffuf superó el timeout de 600s en http://192.168.100.6
```

Soluciones por orden de impacto:

1. Reducir el timeout con `--timeout-fuzz 120` (se cancela antes pero se procesan los resultados parciales).
2. Usar una wordlist más pequeña: `wordlists/default.txt` (por defecto) o `dirb/common.txt`.
3. Verificar que el objetivo responde con latencia razonable (`ping` y `curl -I`).

---

### El módulo de fuzzing termina con 0 rutas descubiertas

- El objetivo puede no servir páginas web en los puertos detectados.
- La wordlist puede no contener las rutas presentes en ese servidor.
- Las respuestas pueden tener códigos no incluidos en el filtro (se filtra 200, 301, 302, 403).

---

### Fase 3 no encuentra vulnerabilidades

Causas habituales:
- Las tecnologías detectadas son muy recientes y Exploit-DB aún no tiene entradas para ellas.
- No se detectó versión exacta en la Fase 2, por lo que los términos de búsqueda son genéricos.
- La base de datos de searchsploit está desactualizada.

Actualizar la base de datos de Exploit-DB:

```bash
sudo searchsploit -u
```

---

### Error de permisos al ejecutar

```
[!] Error de permisos. Ejecuta con sudo.
```

Algunos módulos de nmap (especialmente `--sigiloso` con `-sS`) requieren permisos de root. Ejecuta siempre con `sudo`:

```bash
sudo python3 main.py -t 192.168.100.6
```

---

### El informe no se genera

- Verifica que usaste el flag `--informe`. Por defecto, el informe **no se genera**.
- Verifica que el directorio `informes/` es escribible.
- Comprueba si hay errores al final de la ejecución en la sección de resumen.

---

### ModuleNotFoundError al arrancar

```
ModuleNotFoundError: No module named 'configuracion'
```

Asegúrate de ejecutar desde el directorio raíz del proyecto:

```bash
cd ~/AuditX
sudo python3 main.py -t 192.168.100.6
```

---

## 13. Aviso legal

AuditX ha sido desarrollada con fines **exclusivamente académicos y de investigación** en el contexto del Trabajo Fin de Máster en Ciberseguridad de la Universidad Internacional Isabel I de Castilla.

**El uso de esta herramienta está permitido únicamente:**
- Sobre sistemas propios.
- Sobre sistemas de terceros con autorización explícita y documentada por escrito.
- En entornos de laboratorio controlados (máquinas virtuales, rangos de práctica como HackTheBox, TryHackMe o HackMyVM).

**Queda expresamente prohibido:**
- El uso sobre sistemas sin autorización.
- El uso con fines maliciosos, delictivos o de obtención de acceso no autorizado.

El uso no autorizado de esta herramienta puede constituir un delito informático penado por la legislación vigente (Artículo 197 bis y 264 del Código Penal español, Directiva NIS2, GDPR).

El autor declina toda responsabilidad por el uso indebido de esta herramienta fuera de los contextos autorizados descritos anteriormente.

---

*AuditX v1.0.0 — Martín Gil Blanco — Máster en Ciberseguridad, Universidad Isabel I*
