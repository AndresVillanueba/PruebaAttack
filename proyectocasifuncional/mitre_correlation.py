from opensearchpy import OpenSearch

OPENSEARCH_HOST = "http://localhost:9200"
INDEX_NAME = "mitre-attack"

client = OpenSearch([OPENSEARCH_HOST])

def correlate_service_with_mitre(service_name):
    """
    Busca técnicas MITRE ATT&CK relacionadas con el nombre de un servicio o tecnología.
    :param service_name: str, nombre del servicio detectado (ej: 'SMB', 'RDP', 'Apache')
    :return: lista de técnicas encontradas (dict)
    """
    query = {
        "query": {
            "match": {
                "name": service_name
            }
        }
    }
    response = client.search(index=INDEX_NAME, body=query)
    results = []
    for hit in response["hits"]["hits"]:
        results.append({
            "technique_id": hit["_source"].get("technique_id"),
            "name": hit["_source"].get("name"),
            "description": hit["_source"].get("description"),
            "tactic": hit["_source"].get("tactic"),
            "references": hit["_source"].get("references"),
        })
    return results

# Ejemplo de uso:
if __name__ == "__main__":
    service = "SMB"
    tecnicas = correlate_service_with_mitre(service)
    for t in tecnicas:
        print(f"Técnica: {t['name']} ({t['technique_id']})")
        print(f"Táctica: {t['tactic']}")
        print(f"Descripción: {t['description']}")
        print(f"Referencias: {t['references']}")
        print("---")
