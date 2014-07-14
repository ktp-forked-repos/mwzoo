#!/usr/bin/python
#
# Make sure you run this like:
#  ./bin/celery-yara.py file1 /path/to/file2 [...]
#
import sys
from glob import iglob
import os
import time
import json
import argparse

arg_parser = argparse.ArgumentParser(description="Use celery to parallelize yara analysis across multiple samples")
arg_parser.add_argument('filename', metavar='filename', nargs='+', help='filename(s) to scan')
args = arg_parser.parse_args()

sys.path.append('celery-apps')
from celery import group
from mwzoo_celery.tasks import yara_a_file

g = group(yara_a_file.s(x) for x in args.filename)

r = g.delay()

# Wait for "g" to finish
while not r.ready():
    time.sleep(5)

# The scan has completed
