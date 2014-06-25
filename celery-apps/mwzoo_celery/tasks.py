#!/usr/bin/python
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
def yara_a_file(filename):
    os.system("yara -g -m -s yara/*.yar '{0}' > scans/'{1}'.scan".format(filename, filename.replace('/','_')))
