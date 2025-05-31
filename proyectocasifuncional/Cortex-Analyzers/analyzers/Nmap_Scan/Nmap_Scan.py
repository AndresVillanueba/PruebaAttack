#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import xml.etree.ElementTree as ET
from cortexutils.analyzer import Analyzer

class NmapScan(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        # Lee parámetros de configuración
        self.nmap_args = self.get_param("nmap_args", "-sV -Pn -p 1-1024")

    def run(self):
        target = self.get_data().strip()
        self.report({"status": "start"})

        # Construimos el comando XML
        cmd = f"nmap {self.nmap_args} -oX - {target}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            self.report({
                "errorMessage": f"Nmap error: {e}",
                "input": target
            }, status="fail")
            return

        # Parseamos XML
        root = ET.fromstring(output)
        taxos = []
        full   = []

        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                pnum = port.get("portid")
                proto = port.get("protocol")
                srv   = port.findtext("service/@name") or ""
                vers  = port.findtext("service/@version") or ""
                banner = f"{srv} {vers}".strip()

                # Taxonomía para la tabla resumen
                taxos.append({
                    "predicate": f"Port {pnum}",
                    "namespace": proto,
                    "value": banner or "open"
                })

                # Para full, volcamos todos los datos
                full.append({
                    "port": pnum,
                    "protocol": proto,
                    "service": srv,
                    "version": vers
                })

        # Emitimos los resultados
        self.report({
            "summary": {
                "taxonomies": taxos
            },
            "full": {
                "matches": full
            }
        })

if __name__ == "__main__":
    NmapScan().run()
