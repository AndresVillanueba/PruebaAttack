#!/usr/bin/env python3
import json
import sys
from opensearchpy import OpenSearch, RequestsHttpConnection

# Configura conexión a OpenSearch
def get_client():
    host = 'opensearch'
    port = 9200
    return OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_compress=True,  # mejora rendimiento
        connection_class=RequestsHttpConnection
    )


def ingest_attack_patterns(json_path, index_name='mitre-enterprise-attack'):
    client = get_client()
    # Crea índice si no existe
    if not client.indices.exists(index=index_name):
        client.indices.create(index=index_name)

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Itera objetos y guarda solo tipo 'attack-pattern'
    for obj in data.get('objects', []):
        if obj.get('type') == 'attack-pattern':
            doc_id = obj.get('id')
            client.index(index=index_name, id=doc_id, body=obj)
            print(f"Indexed {doc_id}")

    count = client.count(index=index_name)['count']
    print(f"Ingest complete: {count} attack-patterns indexed in '{index_name}'")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python ingest_mitre.py /path/to/enterprise-attack.json')
        sys.exit(1)
    ingest_attack_patterns(sys.argv[1])
