#!/usr/bin/python
# vim: ts=4:sw=4:et

#
# malware analysis tasks
#

from __future__ import absolute_import
from subprocess import Popen, PIPE
from analysis.celery import celery
from celery import group, chord, chain
import os, os.path
import logging, logging.config
import traceback
import ConfigParser

# PE parsing stuff
import pefile
import bitstring
import string
import bz2
import hashlib
import zlib

#
# Define each of your tasks here:
#
# @celery.task
# def your_task(args, ...):
#    your_results = {}
#    your_results['a'] = do_thing_1()
#    your_results['b'] = do_other_thing()
#    do_another_task(your_results).si()
#    ....
#    return your_results # will not wait for subtask to finish
#

class AnalysisTask(object):
    """Base class for all analysis tasks."""
    def analyze(self, analysis):
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

class YaraAnalysis(ConfigurableAnalysisTask):
    def __init__(self):
        ConfigurableAnalysisTask.__init__(self)

    def analyze(self, analysis):
        args = [ self.config.get('global', 'yara_program') ]
        args.extend(self.config.get('global', 'yara_options').split())
        args.append(self.config.get('global', 'yara_rules'))

        stdout_path = os.path.join(self.config.get('global', 'output_dir'), analysis['hashes']['sha1'] + '.stdout')
        stderr_path = os.path.join(self.config.get('global', 'output_dir'), analysis['hashes']['sha1'] + '.stderr')

        with open(stdout_path, 'wb') as stdout:
            with open(stderr_path, 'wb') as stderr:
                logging.debug("executing {0}".format(' '.join(args)))
                p = Popen(args, stdout=stdout, stderr=stderr)
                p.wait()
                logging.debug("finished executing {0}".format(' '.join(args)))

        analysis['yara']['stdout_path'] = stdout_path
        analysis['yara']['stderr_path'] = stderr_path

        # XXX people could be collecting rules from various places, not sure it makes sense
        # but it would be nice to find a way to know what version of the rules was used
        # is the yara directory a git repo?
        #if os.path.exists(os.path.join(self.config.get('global', 'yara_rules'), '.git')):
            ## record the remotes so we know where it came from
            #p = Popen(['git', '--git-dir', self.config.get('global', 'yara_rules'), 'remote', '-v'], stdout=PIPE)
            #(stdout, stderr) = p.communicate()
            #analysis['yara']['repository'] = stdout

            ## record the current commit so we know what version of the rules was executed
            #p = Popen(['git', '--git-dir', self.config.get('global', 'yara_rules'), 'log', '-n', '1', '--pretty=oneline'], stdout=PIPE)
            #(stdout, stderr) = p.communicate()
            #analysis['yara']['commit'] = stdout

#@celery.task
#def yara_a_file(analysis):
    #"""Scan the file with all of the rules in the yara/ subdirectory."""
    #args = []
    #os.system("yara -g -m -s yara/*.yar '{0}' > scans/'{1}'.scan".format(analysis['storage'], analysis['storage'].replace('/','_')))

class HashAnalysis(AnalysisTask):
    """Perform various hashing algorithms."""
    def analyze(self, analysis):
        with open(analysis['storage'], 'rb') as fp:
            content = fp.read()

        # md5
        m = hashlib.md5()
        m.update(content)
        analysis['hashes']['md5'] = m.hexdigest()

        # sha256
        m = hashlib.sha256()
        m.update(content)
        analysis['hashes']['sha256'] = m.hexdigest()

        # ssdeep
        p = Popen(['ssdeep', analysis['storage']], stdout=PIPE)
        (stdout, stderr) = p.communicate()
        analysis['hashes']['ssdeep'] = stdout

class FileTypeAnalysis(AnalysisTask):
    """Use the file command to record what kind of file this might be."""
    def analyze(self, analysis):
        p = Popen(['file', analysis['storage']], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()

        # example file command output:
        # putty.exe: PE32 executable (GUI) Intel 80386, for MS Windows
        # so len(file_name) + 2 (: + space)
        analysis['file_types'].append(stdoutdata[len(analysis['storage']) + 2:].strip())

        # same thing but for the mime type
        p = Popen(['file', '-i', analysis['storage']], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()
        analysis['mime_types'].append(stdoutdata[len(analysis['storage']) + 2:].strip())

class StringAnalysis(AnalysisTask):
    def analyze(self, analysis):
        """Extract ASCII and "wide" (Unicode) strings."""
        p = Popen(['strings', analysis['storage']], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()
        analysis['strings']['ascii'] = stdoutdata.split('\n')

        p = Popen(['strings', '-e', 'l', analysis['storage']], stdout=PIPE)
        (stdoutdata, stderrdata) = p.communicate()
        analysis['strings']['unicode'] = stdoutdata.split('\n') # <-- XXX spliting Unicode string with ASCII string

class PEAnalysis(AnalysisTask):
    """Parse the PE sections of the file."""

    def analyze(self, analysis):
        try:
            self.exe =  pefile.PE(analysis['storage'], fast_load=True)
        except Exception, e:
            logging.debug("pefile.PE failed: {0}".format(str(e)))
            return

        # call each of these analysis methods
        for analysis_method in [ 
            self._pe_process_sections, 
            self._pe_process_imports, 
            self._pe_process_pehash, 
            self._pe_process_imphash ]:

            try:
                analysis_method(analysis)
            except Exception, e:
                logging.error("{0} failed: {1}".format(analysis_method.__name__, str(e)))
                traceback.print_exc()
        

    def _pe_process_sections(self, analysis):

        # logic for the pesections
        sections = []
        for section in self.exe.sections:
            s = {}
            s['name'] = section.Name
            s['virtual_address'] = hex(section.VirtualAddress)
            s['virtual_size'] = hex(section.Misc_VirtualSize)
            s['raw_size'] = section.SizeOfRawData
            sections.append(s)

        analysis['sections'] = sections

    def _pe_process_imports(self, analysis):
        """logic to calculate imports"""
        analysis['imports'] = []
        imports = []
        for entry in self.exe.DIRECTORY_ENTRY_IMPORT:
            i = {}
            i['name'] = entry.dll
            for imp in entry.imports:
                i['address'] = hex(imp.address)
                i['import_name'] = imp.name 
                analysis['imports'].append(i)

    def _pe_process_exports(self, analysis):
        """logic to calculate exports"""
        analysis['exports'] = []
        imports = []
        for entry in self.exe.DIRECTORY_ENTRY_EXPORT.symbols:
            i = {}
            i['name'] = entry.name
            i['address'] = hex(self.exe.OPTIONAL_HEADER.ImageBase + entry.address)
            i['ordinal'] = entry.ordinal
            analysis['exports'].append(i)

    def _pe_process_pehash(self, analysis):

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

        analysis['hashes']['pehash'] = m.hexdigest()

    def _pe_process_imphash(self, analysis):
        analysis['hashes']['imphash'] = self.exe.get_imphash()

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
            self.decompressed_chunks.append({
                'offset' : self.offset,
                'data' : self.data_buffer})

        self.z = None # zlib decompression object
        self.data_buffer = []
        self.offset = None
    
    def analyze(self, analysis):
        with open(analysis['storage'], 'rb') as fp:
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
        for c in self.decompressed_chunks:
            logging.debug("offset {0} size {1}".format(c['offset'], len(c['data'])))

        # XXX cannot store non UTF-8 strings in mongo??
        # analysis['zlib_blocks'] = decompressed_chunks
