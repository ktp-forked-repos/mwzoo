#!/usr/bin/python
# vim: ts=4:sw=4:et

#
# malware analysis tasks
#

from __future__ import absolute_import
from subprocess import Popen, PIPE
from mwzoo_celery.celery import celery
from celery import group, chord, chain
import os

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
def parse_pe(analysis):
    """Parse the PE sections of the file."""

    import pefile
    
    # TODO is this PE format?
    pe =  pefile.PE(analysis['storage'], fast_load=True)

    # logic for the pesections
    sections = []
    for section in pe.sections:
        s = {}
        s['name'] = '' # ??
        s['virtual_address'] = hex(section.VirtualAddress)
        s['virtual_size'] = hex(section.Misc_VirtualSize)
        s['raw_size'] = section.SizeOfRawData
        #analysis["sections"][section.Name]["VirtualAddress"] = hex(section.VirtualAddress)
        #analysis["sections"][section.Name]["Misc_VirtualSize"] = hex(section.Misc_VirtualSize)
        #analysis["sections"][section.Name]["SizeOfRawData"] = section.SizeOfRawData
        sections.append(s)

        analysis['sections'] = sections
