#!/usr/bin/env python3
import json
from opensearchpy import OpenSearch, helpers

OPENSEARCH_HOST = "http://localhost:9200"
INDEX_NAME = "mitre-attack"

client = OpenSearch([OPENSEARCH_HOST])

def load_mitre_data(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data

def prepare_bulk_actions(data):
    actions = []
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            action = {
                "_index": INDEX_NAME,
                "_source": {
                    "technique_id": obj.get("external_references", [{}])[0].get("external_id", "N/A"),
                    "name": obj.get("name", "N/A"),
                    "description": obj.get("description", ""),
                    "tactic": ", ".join([phase.get("phase_name", "") for phase in obj.get("kill_chain_phases", [])]),
                    "references": [ref.get("url", "") for ref in obj.get("external_references", []) if "url" in ref]
                }
            }
            actions.append(action)
    return actions

def bulk_ingest(file_path):
    data = load_mitre_data(file_path)
    actions = prepare_bulk_actions(data)
    helpers.bulk(client, actions)
    print(f"Ingestados {len(actions)} objetos de MITRE ATT&CK.")

if __name__ == "__main__":
    bulk_ingest("attack-stix-data/enterprise-attack/enterprise-attack-16.1.json")
