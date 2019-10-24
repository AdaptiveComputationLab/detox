import os
import logging

from detection_engine.heuristic import names
from detection_engine.parser import ReportParser, DatasetReportParser

l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)

class Runner(object):
    def __init__(self, rpath, ds_rpath):
        if os.path.exists(rpath):
            self.ds_r = DatasetReportParser(ds_rpath)
            self.rp = ReportParser(rpath)
            self.rp.enumerate_processes()
            dlist_1 = self.rp.list_droppers()
            dlist_2 = self.ds_r.list_droppers()
            if dlist_1 != dlist_2:
                l.debug("droppers mismatch...")

    def detect(self):
        for heuristic, ccall in names.items():
            if ccall(self.rp).detect():
                print("detected by the \"%s\" heuristic..."%heuristic)
