# ATTACK-SENTINEL

Plataforma integral para el análisis de superficie de ataque, correlación con MITRE ATT&CK y gestión de resultados en OpenSearch.

---

## Descripción General
ATTACK-SENTINEL es una solución de ciberseguridad ofensiva que permite analizar dominios e IPs, detectar vulnerabilidades (CVEs), enumerar subdominios, generar informes automáticos y correlacionar hallazgos con la base de conocimiento MITRE ATT&CK. Toda la información se almacena y consulta de forma segura en OpenSearch, permitiendo un historial completo y trazabilidad de los análisis.

---

## Características principales
- **Análisis de superficie de ataque**: Escaneo de puertos, servicios y tecnologías expuestas.
- **Detección de vulnerabilidades (CVEs)**: Consulta de vulnerabilidades públicas asociadas a los servicios detectados.
- **Enumeración de subdominios**: Descubrimiento de subdominios públicos asociados a un dominio objetivo.
- **Correlación con MITRE ATT&CK**: Relaciona los servicios y vulnerabilidades detectadas con técnicas y tácticas MITRE.
- **Generación de informes automáticos**: Informes ejecutivos y técnicos en PDF, incluyendo resumen AI y hallazgos detallados.
- **Gestión de usuarios y autenticación JWT**: Registro, login y control de acceso seguro.
- **Historial y filtrado de análisis**: Consulta y filtrado de análisis previos por usuario y fecha.
- **Integración con OpenSearch**: Almacenamiento cifrado y consulta eficiente de usuarios y análisis.

---

## Estructura del Proyecto

- `/web/` - Interfaz web (frontend y backend Node.js/Express):
  - `index.html`, `scripts.js`, `styles.css`: Interfaz de usuario, lógica de interacción y estilos.
  - `server.js`: API REST, autenticación, integración con OpenSearch y generación de informes.
  - `users.json`: Almacenamiento local de usuarios (además de OpenSearch).
  - `mitre_correlation.js`: Utilidades para correlación MITRE.
- `/attack-stix-data/` - Datos MITRE ATT&CK en formato STIX JSON (enterprise, mobile, ICS, etc.).
- `/Cortex-Analyzers/` - Analyzers y responders para Cortex (no todos interactúan con la plataforma, ver nota abajo).
- `/mitre/` - Scripts y datos para ingesta y correlación MITRE.
- `/Smap/` - Motor de escaneo de puertos y servicios (Go).
- `/tests/` - Pruebas y reportes.
- `results.py`, `ingest_mitre.py`, `mitre_ingest.py`: Scripts para indexar resultados y datos MITRE en OpenSearch.

---

## Instalación y Puesta en Marcha

### 1. Requisitos previos
- Python 3.8+
- Node.js 16+
- OpenSearch 2.x
- (Opcional) Docker para despliegue rápido

### 2. Instalación de dependencias
```bash
# Backend y scripts Python
pip install -r requirements.txt

# Frontend y backend web
cd web
npm install
```

### 3. Configuración de entorno
- Configura las variables de entorno necesarias (OpenSearch, JWT, etc.) en un archivo `.env`.
- Asegúrate de que OpenSearch está corriendo y accesible.

### 4. Ingesta de datos MITRE y arranque
```bash
# Cargar datos MITRE en OpenSearch
python ingest_mitre.py
python mitre_ingest.py

# (Opcional) Indexar resultados de ejemplo
python results.py

# Iniciar la web
cd web
npm start
```

---

## Instalación automática de Ollama

ATTACK-SENTINEL requiere Ollama para la generación de informes automáticos con IA.

### Instalación rápida de Ollama (Linux/Mac/WSL)
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Instalación en Windows
Puedes instalar Ollama fácilmente en Windows ejecutando en PowerShell:
```powershell
irm https://ollama.com/install.ps1 | iex
```
O descarga el instalador desde: https://ollama.com/download

### Integración en Docker
Si usas Docker para levantar la plataforma, añade la instalación de Ollama en tu `Dockerfile` o en el `docker-compose.yml` como un servicio adicional. Ejemplo de servicio Ollama en `docker-compose.yml`:

```yaml
ollama:
  image: ollama/ollama:latest
  ports:
    - "11434:11434"
  volumes:
    - ollama_data:/root/.ollama
volumes:
  ollama_data:
```

Asegúrate de que tu backend Node.js apunte al host y puerto correctos de Ollama (por defecto `localhost:11434` o el nombre del servicio Docker).

---

## Uso de la Plataforma

1. **Registro/Login**: Crea una cuenta o inicia sesión.
2. **Análisis**: Introduce un dominio o IP y selecciona el tipo de análisis.
3. **Resultados**: Visualiza los hallazgos, correlación MITRE y descarga el informe PDF.
4. **Historial**: Consulta y filtra tus análisis anteriores.
5. **MITRE Info**: Consulta la base de técnicas MITRE ATT&CK desde la web.

---

## Integración con OpenSearch
- Los usuarios y análisis se almacenan cifrados en OpenSearch.
- Los scripts Python permiten ingestar datos MITRE y resultados históricos.
- El backend Node.js consulta y almacena usuarios y análisis en tiempo real.

---

## Seguridad
- Autenticación JWT para todas las rutas críticas.
- Contraseñas hasheadas (bcrypt).
- Datos de análisis cifrados antes de almacenarse.

---

## Personalización y Extensión
- Puedes añadir nuevos analizadores en `/Cortex-Analyzers/` (solo los que uses en tu flujo).
- Los datos MITRE pueden actualizarse descargando nuevos JSON STIX y re-ejecutando los scripts de ingesta.
- El frontend es fácilmente personalizable en `/web/`.

---

## Archivos y carpetas que puedes eliminar si no usas:
- `/Cortex-Analyzers/` (excepto los analizadores que realmente uses en tu flujo)
- `/tests/` si no necesitas los reportes de prueba
- `/attack-stix-data/ics-attack/`, `/attack-stix-data/mobile-attack/` si solo usas enterprise-attack
- Cualquier README, CHANGELOG o archivo de ejemplo que no aporte a tu despliegue real

---

## Créditos y Licencia
- MITRE ATT&CK: https://attack.mitre.org/
- Proyecto basado en Node.js, Python y OpenSearch
- Licencia: Ver LICENSE.txt
