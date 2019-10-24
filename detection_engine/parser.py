import json
import ntpath
import logging

from misc import Process, API, APIStats

logging.basicConfig()
l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)

class ReportParser(object):
    def __init__(self, filename):
        self.filename = filename
        self.processes = []
        self.stats = []
        self.dropper = set()
        self.report = self.parse(self.filename)

    @staticmethod
    def parse(filename):
        return json.loads(open(filename).read())

    def enumerate_processes(self):
        processes = self.report['behavior']['processes']
        for p in processes:
            process = Process(p)
            if p['calls']:
                for api_call in p['calls']:
                    api = API(api_call)
                    process.call_chain(api)
            self.processes.append(process)

    def api_stats(self):
        stats = self.report['behavior']['apistats']
        for pid, stat in stats.items():
            self.stats.append(APIStats(pid, stat))

    def list_droppers(self):
        tasks = self.report['behavior']['generic']
        for task in tasks:
            if 'file_written' not in task['summary'].keys():
                continue
            files = task['summary']['file_written']
            for f in files:
                process_name = task['process_name']
                exe_name = ntpath.basename(f)
                l.debug('%s -> %s '%(process_name, exe_name))
                self.dropper.add(exe_name)
        return self.dropper

class DatasetReportParser(ReportParser):
    def __init__(self, fname):
        self.type_list = ['VBSVisualBasicScriptFile', 'PeExeFile']
        super(DatasetReportParser, self).__init__(fname)


    def list_droppers(self):

        def isexec(fobj):
            if 'ext_info' in fobj.keys():
                ftype = fobj['ext_info']['llfile']
                if ftype in self.type_list:
                    return True
            else:
                False

        subjects = self.report['data']['report']['analysis_subjects']
        for subject in subjects:
            if 'file_writes' not in subject.keys():
                continue
            writes = subject['file_writes']
            for write in writes:
                if 'accesses' not in write.keys():
                    continue
                status = write['iostatus']
                if "FILE_CREATED" in status:
                    if isexec(write):
                        exe_name = ntpath.basename(write['abs_path'])
                        process_name = ntpath.basename(subject['process']['executable']['filename'])
                        l.debug('%s -> %s '%(process_name, exe_name))
                        self.dropper.add(exe_name)
                    else:
                        continue
        return self.dropper
