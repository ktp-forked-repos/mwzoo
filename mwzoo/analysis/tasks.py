#!/usr/bin/python
# vim: ts=4:sw=4:et

#
# malware analysis tasks
#

from subprocess import Popen, PIPE
import os, os.path
import logging, logging.config
import traceback
import ConfigParser
import time
import json
import requests
import re

# PE parsing stuff
import pefile
import bitstring
import string
import bz2
import hashlib
import zlib

#
# use this class as the base class for all analysis tasks
# all analysis tasks are loaded dynamically at run time
# if your task uses the analysis output of another task
# then add an attribute called depends_on that is a list of the AnalysisTask-based objects that need to run
#
# example
# 
        # file type analysis must be done
        # self.depends_on = [ FileTypeAnalysis ]

class AnalysisTask(object):
    """Base class for all analysis tasks."""
    def analyze(self, sample):
        """Override this method to provide analysis.  The analysis storage container is passed as the only argument."""
        raise NotImplementedError()

class ConfigurationRequiredError(Exception):
    pass

class ConfigurableAnalysisTask(AnalysisTask):
    def __init__(self):
        AnalysisTask.__init__(self)
        self.load_configuration()

    def load_configuration(self):
        """Loads the configuration file for the current analysis object from
$MWZOO_HOME/etc/analysis/$CLASS_NAME.ini"""

        config_path = os.path.join(os.environ['MWZOO_HOME'], 'etc', 'analysis', self.__class__.__name__ + '.ini')
        if not os.path.exists(config_path):
            raise ConfigurationRequiredError()

        self.config = ConfigParser.ConfigParser()
        self.config.read(config_path)

    def load_json_configuration(self):
        """ (Optionally) load a json configuration file for the current analysis object from
$MWZOO_HOME/etc/analysis/$CLASS_NAME.json"""

        json_path = os.path.join(os.environ['MWZOO_HOME'], 'etc', 'analysis', self.__class__.__name__ + '.json')
        if not os.path.exists(json_path):
            raise ConfigurationRequiredError()

        with open(json_path, 'rb') as fp:
            data = fp.read()
            print data
            self.config = json.loads(data)

class SsdeepAnalysis(AnalysisTask):
    """Compute ssdeep hash of the sample."""
    def analyze(self, sample):
        p = Popen(['ssdeep', sample.content_path], stdout=PIPE, stderr=PIPE)
        (stdout, stderr) = p.communicate()
        return { 'hash': stdout }

class YaraAnalysis(ConfigurableAnalysisTask):
    def __init__(self):
        ConfigurableAnalysisTask.__init__(self)

    def analyze(self, sample):
        args = [ self.config.get('global', 'yara_program') ]
        args.extend(self.config.get('global', 'yara_options').split())
        args.append(self.config.get('global', 'yara_rules'))

        storage_dir = os.path.join(sample.storage_path, self.config.get('global', 'output_dir'))
        os.makedirs(storage_dir)

        stdout_path = os.path.join(storage_dir, sample.sha1_hash + '.stdout')
        stderr_path = os.path.join(storage_dir, sample.sha1_hash + '.stderr')

        with open(stdout_path, 'wb') as stdout:
            with open(stderr_path, 'wb') as stderr:
                logging.debug("executing {0}".format(' '.join(args)))
                p = Popen(args, stdout=stdout, stderr=stderr)
                p.wait()
                logging.debug("finished executing {0}".format(' '.join(args)))

        return {
            'stdout_path': stdout_path,
            'stderr_path': stderr_path
        }

        # XXX people could be collecting rules from various places, not sure it makes sense
        # but it would be nice to find a way to know what version of the rules was used
        # is the yara directory a git repo?
        #if os.path.exists(os.path.join(self.config.get('global', 'yara_rules'), '.git')):
            ## record the remotes so we know where it came from
            #p = Popen(['git', '--git-dir', self.config.get('global', 'yara_rules'), 'remote', '-v'], stdout=PIPE)
            #(stdout, stderr) = p.communicate()
            #sample.analysis['yara']['repository'] = stdout

            ## record the current commit so we know what version of the rules was executed
            #p = Popen(['git', '--git-dir', self.config.get('global', 'yara_rules'), 'log', '-n', '1', '--pretty=oneline'], stdout=PIPE)
            #(stdout, stderr) = p.communicate()
            #sample.analysis['yara']['commit'] = stdout

class FileTypeAnalysis(AnalysisTask):
    """Use the file command to record what kind of file this might be."""
    #def __init__(self):
        #AnalysisTask.__init__(self)
        #self.depends_on = [ CuckooAnalysis ]

    def analyze(self, sample):

        result = { 'file_types': [], 'mime_types': [] }

        p = Popen(['file', sample.content_path], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()

        # example file command output:
        # putty.exe: PE32 executable (GUI) Intel 80386, for MS Windows
        # so len(file_name) + 2 (: + space)
        result['file_types'].append(stdoutdata[len(sample.analysis['storage']) + 2:].strip())

        # same thing but for the mime type
        p = Popen(['file', '-i', sample.analysis['storage']], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()
        result['mime_types'].append(stdoutdata[len(sample.analysis['storage']) + 2:].strip())

        return result

class StringAnalysis(AnalysisTask):
    def analyze(self, sample):
        """Extract ASCII and "wide" (Unicode) strings."""
        result = { 'ascii': [], 'unicode': [] }
        p = Popen(['strings', sample.content_path], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()
        result['ascii'] = stdoutdata.split('\n')

        p = Popen(['strings', '-e', 'l', sample.content_path], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()
        result['unicode'] = stdoutdata.split('\n') # <-- XXX spliting Unicode string with ASCII string

        return result

class PEAnalysis(AnalysisTask):
    """Parse the PE sections of the file."""

    def analyze(self, sample):
        try:
            self.exe =  pefile.PE(sample.content_path, fast_load=True)
        except Exception, e:
            logging.debug("pefile.PE failed: {0}".format(str(e)))
            return { }

        result = { }

        # call each of these analysis methods
        for analysis_method in [ 
            self._pe_process_sections, 
            self._pe_process_imports, 
            self._pe_process_pehash, 
            self._pe_process_imphash ]:

            try:
                analysis_method(sample, result)
            except Exception, e:
                logging.error("{0} failed: {1}".format(analysis_method.__name__, str(e)))
                traceback.print_exc()

        return result

    def _pe_process_sections(self, sample, result):

        # logic for the pesections
        sections = []
        for section in self.exe.sections:
            s = {}
            s['name'] = section.Name
            s['virtual_address'] = hex(section.VirtualAddress)
            s['virtual_size'] = hex(section.Misc_VirtualSize)
            s['raw_size'] = section.SizeOfRawData
            sections.append(s)

        result['sections'] = sections

    def _pe_process_imports(self, sample, result):
        """logic to calculate imports"""
        result['imports'] = []
        imports = []
        for entry in self.exe.DIRECTORY_ENTRY_IMPORT:
            i = {}
            i['name'] = entry.dll
            for imp in entry.imports:
                i['address'] = hex(imp.address)
                i['import_name'] = imp.name 
                result['imports'].append(i)

    def _pe_process_exports(self, sample, result):
        """logic to calculate exports"""
        result['exports'] = []
        imports = []
        for entry in self.exe.DIRECTORY_ENTRY_EXPORT.symbols:
            i = {}
            i['name'] = entry.name
            i['address'] = hex(self.exe.OPTIONAL_HEADER.ImageBase + entry.address)
            i['ordinal'] = entry.ordinal
            result['exports'].append(i)

    def _pe_process_pehash(self, sample, result):

        #
        # compute pehash
        #

        #image characteristics
        img_chars = bitstring.BitArray(hex(self.exe.FILE_HEADER.Characteristics))
        #pad to 16 bits
        img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
        img_chars_xor = img_chars[0:7] ^ img_chars[8:15]

        #start to build pehash
        pehash_bin = bitstring.BitArray(img_chars_xor)

        #subsystem - 
        sub_chars = bitstring.BitArray(hex(self.exe.FILE_HEADER.Machine))
        #pad to 16 bits
        sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
        sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
        pehash_bin.append(sub_chars_xor)

        #Stack Commit Size
        stk_size = bitstring.BitArray(hex(self.exe.OPTIONAL_HEADER.SizeOfStackCommit))
        stk_size_bits = string.zfill(stk_size.bin, 32)
        #now xor the bits
        stk_size = bitstring.BitArray(bin=stk_size_bits)
        stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
        #pad to 8 bits
        stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
        pehash_bin.append(stk_size_xor)

        #Heap Commit Size
        hp_size = bitstring.BitArray(hex(self.exe.OPTIONAL_HEADER.SizeOfHeapCommit))
        hp_size_bits = string.zfill(hp_size.bin, 32)
        #now xor the bits
        hp_size = bitstring.BitArray(bin=hp_size_bits)
        hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
        #pad to 8 bits
        hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
        pehash_bin.append(hp_size_xor)

        #Section chars
        for section in self.exe.sections:
            #virutal address
            sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
            sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
            pehash_bin.append(sect_va)    

            #rawsize
            sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = string.zfill(sect_rs.bin, 32)
            sect_rs = bitstring.BitArray(bin=sect_rs_bits)
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs[8:31]
            pehash_bin.append(sect_rs_bits)

            #section chars
            sect_chars =  bitstring.BitArray(hex(section.Characteristics))
            sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
            sect_chars_xor = sect_chars[16:23] ^ sect_chars[24:31]
            pehash_bin.append(sect_chars_xor)

            #entropy calulation
            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = self.exe.write()[address+size:]
            if size == 0: 
                kolmog = bitstring.BitArray(float=1, length=32)
                pehash_bin.append(kolmog[0:7])
                continue
            bz2_raw = bz2.compress(raw)
            bz2_size = len(bz2_raw)
            #k = round(bz2_size / size, 5)
            k = bz2_size / size
            kolmog = bitstring.BitArray(float=k, length=32)
            pehash_bin.append(kolmog[0:7])

        m = hashlib.sha1()
        m.update(pehash_bin.tobytes())

        result['pehash'] = m.hexdigest()

    def _pe_process_imphash(self, sample, result):
        result['imphash'] = self.exe.get_imphash()

class ZlibAnalysis(AnalysisTask):
    """Perform a brute force zlib decompression attempt against every byte in the file."""

    def __init__(self):
        AnalysisTask.__init__(self)

        self.decompressed_chunks = []
        self.z = None # zlib decompression object
        self.data_buffer = []
        self.offset = None
        self._reset_decompression()

    def _reset_decompression(self):
        if len(self.data_buffer) > 0:
            logging.debug("added {0} {1}".format(self.offset, len(self.data_buffer)))
            self.decompressed_chunks.append({
                'offset' : self.offset,
                'content' : ''.join(self.data_buffer)})

        self.z = None # zlib decompression object
        self.data_buffer = []
        self.offset = None
    
    def analyze(self, sample):
        with open(sample.content_path, 'rb') as fp:
            while True:
                byte = fp.read(1)
                # EOF?
                if byte == '':
                    break

                # are we currently decompressing?
                if self.z is not None:
                    try:
                        result = self.z.decompress(byte)
                        # did we get a decompressed chunk out?
                        if result:
                            self.data_buffer.extend(result)
                        # is decompression finished?
                        if self.z.unused_data != '':
                            self._reset_decompression()
                        else:
                            continue
                    except zlib.error:
                        self._reset_decompression()

                # zlib compresses data starts with an 'x'
                if self.z is None and byte == 'x':
                    self.z = zlib.decompressobj()
                    self.z.decompress(byte)
                    self.offset = fp.tell()

            # remaining data_buffer
            self._reset_decompression()

        logging.debug("found {0} compressed chunks".format(len(self.decompressed_chunks)))

        if len(self.decompressed_chunks) > 0:
            # store the chunks into the file system
            storage_dir = os.path.join(sample.storage_path, 'zlib_blocks')
            os.makedirs(storage_dir)

            for c in self.decompressed_chunks:
                content_path = os.path.join(storage_dir, "{0}.decompressed".format(c['offset']))
                with open(content_path, 'wb') as zlib_out:
                    logging.debug(
"writing decompressed zlib block from offset {0} size {1} to {2}".format(
    c['offset'], 
    len(c['content']),
    content_path))
                    zlib_out.write(c['content'])
                    del c['content']
                    c['content_path'] = content_path

            return { 'blocks':  self.decompressed_chunks }

class CuckooAnalysis(ConfigurableAnalysisTask):
    """Execute the file in the configured cuckoo environment."""
    
    def __init__(self):
        ConfigurableAnalysisTask.__init__(self)

        # make sure there are no proxy env settings
        if 'http_proxy' in os.environ:
            logging.warning("removing proxy {0}".format(os.environ['http_proxy']))
            del os.environ['http_proxy']

        # XXX load json configuration
        self.load_json_configuration()

        self.base_url = self.config['base_url']
        self.autosubmit = self.config['autosubmit']

        # file type analysis must be done
        self.depends_on = [ FileTypeAnalysis ]

    def _get_analysis(self, sample):
        """Loads (or refreshes) the cuckoo analysis for the given sample."""

        result = { 'analysis': [] }

        try:
            r = requests.get('{0}/files/view/md5/{1}'.format(self.base_url, sample.md5_hash))
        except Exception, e:
            logging.error("requests.get() called failed: {0}".format(sample))
            traceback.print_exc()
            return result

        if r.status_code == 200:
            logging.debug("analysis available for {0}".format(sample))
            file_info = r.json()
            sample_id = file_info['sample']['id']

            # find all the tasks that reference this sample_id
            r = requests.get('{0}/tasks/list'.format(self.base_url))
            if r.status_code == 200:
                tasks = r.json()
                tasks = tasks['tasks']
                logging.debug("received {0} tasks".format(len(tasks)))
                for task in tasks:
                    if task['category'] == 'file' and task['sample_id'] == sample_id:
                        # query for the report of this task
                        logging.debug("querying task id {0}".format(task['id']))
                        r = requests.get('{0}/tasks/report/{1}'.format(self.base_url, task['id']))
                        if r.status_code == 200:
                            logging.debug("downloading report for {0}".format(task['id']))
                            report = r.json()

                            # we're only going to record a subset of the information    
                            # TODO query for the config of the machine that executed and filter out the 
                            # TODO traffic generated by the reporting
                            result['analysis'].append({
                                'sandbox_name': 'cuckoo',
                                'sandbox_version': report['info']['version'],
                                'image_name': report['info']['machine'], # TODO this may not be working
                                'network': report['network'],
                                'summary': report['behavior']['summary']
                            })

                        else:
                            logging.error("query for task id {0} returned {1}".format(task['id'], r.status_code))
            else:
                logging.error("query for task list returned {0}".format(r.status_code))

            logging.debug("received {0} reports for sample {1}".format(len(result['analysis']), sample))

        return result

    def _submit(self, sample):
        """Submits a sample to the cuckoo server for analysis, waits for the results."""

        # determine what machine to use based on the analysis performed by the FileType analysis module
        # TODO only using mime_types at this point, expand to others
        target_machines = []
        for machine in self.config['mapping'].keys():
            for mime_type in self.config['mapping'][machine]['mime_types']:
                # XXX see if there is a way to get rid of hard coded module name
                file_type_analysis = sample.get_analysis('FileTypeAnalysis')
                assert file_type_analysis is not None
                if any([mime_type in x for x in file_type_analysis['details']['mime_types']]):
                    logging.debug("found machine {0} for mime_type {1}".format(machine, mime_type))
                    target_machines.append(machine)

        if len(target_machines) < 1:
            logging.debug("no target machines found")
            return

        task_ids = []
        for machine in target_machines:
            logging.info("submitting sample {0} to machine {1}".format(sample.md5_hash, machine))
            with open(sample.content_path, 'rb') as fp:
                r = requests.post(
                    '{0}/tasks/create/file'.format(self.base_url), 
                    files= { 'file': ( sample.analysis['names'][0], fp ) },
                    data = { 'machine': machine })
                if r.status_code != 200:
                    logging.error(
"unable to submit sample {0} to machine {1}: {2}".format(
sample, machine, str(r)))
                    return

                r = r.json()
                task_id = r['task_id']
                logging.debug("got task_id {0}".format(task_id))
                task_ids.append(task_id)

        # wait for them to finish
        logging.debug("waiting for analysis to finish")
        while True:

            time.sleep(1)

            error = False
            finished_count = 0
            for task_id in task_ids:
                try:
                    r = requests.get('{0}/tasks/view/{1}'.format(self.base_url, task_id))
                    if r.status_code == 200:
                        r = r.json()
                        status = r['task']['status']
                        #logging.debug("got status {0} for task {1}".format(status, task_id))
                        if status == 'reported':
                        #if status != 'pending' and status != 'running':
                            logging.debug('detected status {0}'.format(status))
                            finished_count += 1
                    else:
                        raise Exception("invalid status code {0}".format(r.status_code))
                except Exception, e:
                    logging.error(
"caught exception when querying task(s) status: {0}".format(str(e)))
                    traceback.print_exc()
                    error = True
                    break

            if error:
                break

            if finished_count == len(task_ids):
                break

            #logging.debug("finished count = {0}".format(finished_count))
        
    def analyze(self, sample):
        """Attempt to download existing cuckoo analysis, or submit the sample for analysis."""

        result = self._get_analysis(sample)
        if len(result['analysis']) < 1:
            # are we subumitting new samples to the sandbox?
            if self.config['autosubmit']:
                self._submit(sample)
                result = self._get_analysis(sample)

        return result

class ExifToolAnalysis(AnalysisTask):
    """Record the output of the exiftool software."""
    def analyze(self, sample):
        result = {}
        p = Popen(['exiftool', sample.content_path], stdout=PIPE, stderr=PIPE)
        (stdout, stderr) = p.communicate()
        for line in stdout.split('\n'):
            m = re.match(r'^([^:]+):(.+)$', line)
            if m:
                (key, value) = m.groups()
                key = key.strip()
                value = value.strip()
                logging.debug("exif tool key {0} value {1}".format(key, value))
                result[key] = value
