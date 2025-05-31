#!/usr/bin/env python3
import json
from opensearchpy import OpenSearch, helpers

# URL de Opensearch
OPENSEARCH_URL = "http://opensearch:9200"

# Cliente
es = OpenSearch(OPENSEARCH_URL)

# Carga el JSON de MITRE
with open("/data/enterprise-attack.json", "r", encoding="utf-8") as f:
    ttx = json.load(f)

# Filtra sólo los objetos de tipo "attack-pattern"
actions = []
for obj in ttx["objects"]:
    if obj.get("type") == "attack-pattern":
        actions.append({
            "_index": "mitre-attack",
            "_id": obj["id"],
            "_source": {
                "name": obj.get("name"),
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "external_references": obj.get("external_references", [])
            }
        })

# Inserción masiva
helpers.bulk(es, actions)
print(f"✅ Indexadas {len(actions)} técnicas MITRE ATT&CK")
