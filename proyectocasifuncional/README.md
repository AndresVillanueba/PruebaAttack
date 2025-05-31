# attack-sentinel

Plataforma para análisis de superficie de ataque y correlación con MITRE ATT&CK.

## Descripción
Este proyecto permite analizar dominios/IPs, buscar vulnerabilidades (CVEs), enumerar subdominios y generar informes automáticos, integrando resultados con MITRE ATT&CK y almacenando los datos en OpenSearch.

## Estructura principal
- `ingest_mitre.py`, `mitre_ingest.py`: Scripts para cargar y procesar datos de MITRE ATT&CK en OpenSearch.
- `results.py`: Indexa resultados de análisis en OpenSearch.
- `web/`: Interfaz web y API para usuarios.
- `Cortex-Analyzers/`: Analyzers y utilidades para Cortex.

## Uso rápido
1. Instala dependencias: `pip install -r requirements.txt` y `npm install` en la carpeta `web`.
2. Configura OpenSearch y variables de entorno necesarias.
3. Ejecuta los scripts de ingesta para cargar datos MITRE.
4. Inicia la interfaz web con `npm start` en la carpeta `web`.

## Dependencias principales
- Python: `opensearch-py`, `helpers`
- Node.js: `express`, `axios`, `@opensearch-project/opensearch`, `jsonwebtoken`

## Licencia
Ver archivo LICENSE.txt o LICENSE en cada subproyecto.
