#!/usr/bin/python
# vim: ts=4:sw=4:et

#
# malware analysis tasks
#

from __future__ import absolute_import
from subprocess import Popen, PIPE
from analysis.celery import celery
from celery import group, chord, chain
import os
import logging, logging.config
import traceback

# PE parsing stuff
import pefile
import bitstring
import string
import bz2
import hashlib

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

@celery.task
def yara_a_file(analysis):
    """Scan the file with all of the rules in the yara/ subdirectory."""
    os.system("yara -g -m -s yara/*.yar '{0}' > scans/'{1}'.scan".format(analysis['storage'], analysis['storage'].replace('/','_')))

@celery.task
def hash_contents(analysis):

    """Perform various hashing algorithms."""
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
    p.wait()
    analysis['hashes']['ssdeep'] = p.stdout.read()

def _pe_process_sections(analysis):

    # TODO pass this as an argument
    exe =  pefile.PE(analysis['storage'], fast_load=True)

    # logic for the pesections
    sections = []
    for section in exe.sections:
        s = {}
        s['name'] = section.Name
        s['virtual_address'] = hex(section.VirtualAddress)
        s['virtual_size'] = hex(section.Misc_VirtualSize)
        s['raw_size'] = section.SizeOfRawData
        sections.append(s)

    analysis['sections'] = sections

def _pe_process_imports(analysis):
    """logic to calculate imports"""
    exe =  pefile.PE(analysis['storage'], fast_load=True)
    analysis['imports'] = []
    imports = []
    for entry in exe.DIRECTORY_ENTRY_IMPORT:
        i = {}
        i['name'] = entry.dll
        for imp in entry.imports:
            i['address'] = hex(imp.address)
            i['import_name'] = imp.name 
        analysis['imports'].append(i)

def _pe_process_exports(analysis):
    """logic to calculate exports"""
    exe =  pefile.PE(analysis['storage'], fast_load=True)
    analysis['exports'] = []
    imports = []
    for entry in exe.DIRECTORY_ENTRY_EXPORT.symbols:
        i = {}
        i['name'] = entry.name
        i['address'] = hex(exe.OPTIONAL_HEADER.ImageBase + entry.address)
        i['ordinal'] = entry.ordinal
        analysis['exports'].append(i)

def _pe_process_pehash(analysis):
    exe =  pefile.PE(analysis['storage'], fast_load=True)

    #
    # compute pehash
    #

    #image characteristics
    img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
    #pad to 16 bits
    img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
    img_chars_xor = img_chars[0:7] ^ img_chars[8:15]

    #start to build pehash
    pehash_bin = bitstring.BitArray(img_chars_xor)

    #subsystem - 
    sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
    #pad to 16 bits
    sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
    sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
    pehash_bin.append(sub_chars_xor)

    #Stack Commit Size
    stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
    stk_size_bits = string.zfill(stk_size.bin, 32)
    #now xor the bits
    stk_size = bitstring.BitArray(bin=stk_size_bits)
    stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
    #pad to 8 bits
    stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
    pehash_bin.append(stk_size_xor)

    #Heap Commit Size
    hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
    hp_size_bits = string.zfill(hp_size.bin, 32)
    #now xor the bits
    hp_size = bitstring.BitArray(bin=hp_size_bits)
    hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
    #pad to 8 bits
    hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
    pehash_bin.append(hp_size_xor)

    #Section chars
    for section in exe.sections:
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
        raw = exe.write()[address+size:]
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

def _pe_process_imphash(analysis):
    exe =  pefile.PE(analysis['storage'], fast_load=True)
    analysis['hashes']['imphash'] = exe.get_imphash()


@celery.task
def parse_pe(analysis):
    """Parse the PE sections of the file."""

    # call each of these analysis methods
    for analysis_method in [ 
        _pe_process_sections, 
        _pe_process_imports, 
        _pe_process_pehash, 
        _pe_process_imphash ]:

        try:
            analysis_method(analysis)
        except Exception, e:
            logging.error("{0} failed: {1}".format(analysis_method.__name__, str(e)))
            traceback.print_exc()

@celery.task
def extract_strings(analysis):
    """Extract ASCII and "wide" (Unicode) strings."""
    p = Popen(['strings', analysis['storage']], stdout=PIPE)
    (stdoutdata, stderrdata) = p.communicate()
    analysis['strings']['ascii'] = stdoutdata.split('\n')

    p = Popen(['strings', '-e', 'l', analysis['storage']], stdout=PIPE)
    (stdoutdata, stderrdata) = p.communicate()
    analysis['strings']['unicode'] = stdoutdata.split('\n')

@celery.task
def detect_file_type(analysis):
    """Detect what kind of file this is."""
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
