#!/usr/bin/env python
# vim: ts=4:sw=4:et
#
# malware zoo
#

from mwzoo import MalwareZoo
import argparse
import os
import logging

parser = argparse.ArgumentParser(description='MalwareZoo')
parser.add_argument(
    '-c', '--config-path', action='store', dest='config_path', default='etc/mwzoo.ini', required=False,
    help='Path to configuration file for the malware zoo.')
args = parser.parse_args()

if not os.path.exists(args.config_path):
    sys.stderr.write('missing configuration file {0}\n'.format(args.config_path))
    sys.exit(1)

#logging.config.dictConfig(log_config)
logging.config.fileConfig('etc/logging.conf')

logging.debug("starting malware zoo")
malware_zoo = MalwareZoo()
malware_zoo.load_global_config(args.config_path)
malware_zoo.start()
