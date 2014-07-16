#!/usr/bin/env python
# vim: ts=4:sw=4:et
#
# malware zoo
#

import mwzoo
import argparse
import os
import logging

parser = argparse.ArgumentParser(description='MalwareZoo')
parser.add_argument(
    '--mwzoo-home', action='store', dest='mwzoo_home', default=None, required=False,
    help='Path to the base installation directory of the malware zoo.  This overrides MWZOO_HOME environment variable, if set.')
parser.add_argument(
    '-c', '--config-path', action='store', dest='config_path', default='etc/mwzoo.ini', required=False,
    help='Path to configuration file for the malware zoo.')
parser.add_argument(
    '--logging-config-path', action='store', dest='logging_config_path', default='etc/logging.ini', required=False,
    help='Path to logging configuration file for the malware zoo.')
args = parser.parse_args()

if args.mwzoo_home is not None:
    os.environ['MWZOO_HOME'] = args.mwzoo_home

# if we don't specify a directory then we default to cwd
if 'MWZOO_HOME' not in os.environ:
    os.environ['MWZOO_HOME'] = '.'

try:
    os.chdir(os.environ['MWZOO_HOME'])
except Exception, e:
    sys.stderr.write("unable to change working directory to {0}: {1}\n",
        os.environ['MWZOO_HOME'], str(e))
    sys.exit(1)

logging.config.fileConfig(args.logging_config_path)

mwzoo.load_global_config(args.config_path)

logging.info("starting malware zoo http server")
mwzoo.HTTPServer().start()
