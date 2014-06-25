#!/usr/bin/python
from __future__ import absolute_import
from subprocess import Popen, PIPE
from mwzoo_celery.celery import celery
from celery import group, chord, chain
import os

@celery.task
def yara_a_file(filename):
    os.system("yara -g -m -s yara/*.yar '{0}' > scans/'{1}'.scan".format(filename, filename.replace('/','_')))
