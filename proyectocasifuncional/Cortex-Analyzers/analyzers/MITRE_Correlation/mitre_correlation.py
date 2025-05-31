#!/usr/bin/env python3
import os, json
from cortexutils.analyzer import Analyzer
from opensearchpy import OpenSearch

class MitreCorrelation(Analyzer):
    def __init__(self):
        super().__init__()
        # lee el host de opensearch de la config (te lo pasaremos en plugin.json)
        es_uri = self.get_param("config.es_uri", "http://opensearch:9200")
        self.es = OpenSearch(es_uri)
    def run(self):
        data = self.get_param("data", None, "Data is missing")
        # buscamos en el índice mitre-attack
        q = {"query":{"match":{"name": data}}}
        res = self.es.search(index="mitre-attack", body=q)
        hits = res["hits"]["hits"]
        # construimos taxonomías con las técnicas encontradas
        taxo = []
        for h in hits:
            src = h["_source"]
            tech = src.get("technique_id","?")
            name = src["name"]
            taxo.append(self.build_taxonomy("info", "MITRE", tech, name))
        self.report({"taxonomies": taxo})

if __name__ == "__main__":
    MitreCorrelation().run()
