#!/usr/bin/env python3
"""
Script para indexar resultados de análisis en OpenSearch.
"""
import json
import sys
from datetime import datetime
from opensearchpy import OpenSearch, helpers

OPENSEARCH_HOST = "http://localhost:9200"
INDEX_NAME = "cortex-analyses"

client = OpenSearch([OPENSEARCH_HOST])

def index_document(doc):
    """Indexa un solo documento en OpenSearch."""
    doc['indexed_at'] = datetime.utcnow().isoformat()
    response = client.index(index=INDEX_NAME, body=doc)
    print(f"Documento indexado, ID: {response['_id']}")

def bulk_index_documents(docs):
    """Indexa múltiples documentos en OpenSearch usando bulk."""
    actions = [
        {
            "_index": INDEX_NAME,
            "_source": {**doc, "indexed_at": datetime.utcnow().isoformat()}
        }
        for doc in docs
    ]
    helpers.bulk(client, actions)
    print(f"Se indexaron {len(docs)} documentos.")

def main():
    """Carga resultados desde un archivo JSON y los indexa en OpenSearch."""
    try:
        with open("resultados.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        print("Archivo de resultados no encontrado:", e)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("Error de formato JSON en el archivo de resultados:", e)
        sys.exit(1)
    except Exception as e:
        print("Error inesperado al leer el archivo de resultados:", e)
        sys.exit(1)
    
    if isinstance(data, dict):
        index_document(data)
    elif isinstance(data, list):
        bulk_index_documents(data)
    else:
        print("Formato de datos no reconocido")
        sys.exit(1)

if __name__ == "__main__":
    main()
