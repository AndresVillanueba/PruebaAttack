#!/usr/bin/env python3
# encoding: utf-8
import subprocess
import sys
from cortexutils.analyzer import Analyzer

class SmapScan(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def run(self):
        target = self.get_param('data')
        cmd = ['smap', target]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            self.report({'output': out.decode()})
        except Exception as e:
            self.error(f"Smap error: {e}")

if __name__ == '__main__':
    SmapScan().run()