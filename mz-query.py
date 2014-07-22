#!/usr/bin/env python
# vim: ts=4:sw=4:et
import argparse
import os.path
import shutil
import mwzoo
import json

parser = argparse.ArgumentParser(description='Malware Zoo Sample Query')

# standard options TODO - refactor
parser.add_argument(
    '--mwzoo-home', action='store', dest='mwzoo_home', default=None, required=False,
    help='Path to the base installation directory of the malware zoo.  This overrides MWZOO_HOME environment variable, if set.')
parser.add_argument(
    '-c', '--config-path', action='store', dest='config_path', default='etc/mwzoo.ini', required=False,
    help='Path to configuration file for the malware zoo.')

# storage options
parser.add_argument(
    '-d', '--directory', action='store', dest='directory', required=False, default=None,
    help="Store matching files in the given directory.")

# query options
parser.add_argument(
    '-5', '--md5', action='store', dest='md5', required=False, default=None,
    help="Query by md5 hash (regex pattern).")

parser.add_argument(
    '-1', '--sha1', action='store', dest='sha1', required=False, default=None,
    help="Query by sha1 hash (regex pattern).")

parser.add_argument(
    '-n', '--file-name', action='store', dest='file_name', required=False, default=None,
    help="Query by file name (regex pattern).")

parser.add_argument(
    '--mime-type', action='store', dest='mime_type', required=False, default=None,
    help="Query by mime type (regex pattern).")

parser.add_argument(
    '--file-type', action='store', dest='file_type', required=False, default=None,
    help="Query by file type (regex pattern).")

parser.add_argument(
    '-t', '--tag', action='store', dest='tag', required=False, default=None,
    help="Query by tag (regex pattern).")

parser.add_argument(
    '-s', '--source', action='store', dest='source', required=False, default=None,
    help="Query by source (regex pattern).")

# output options
parser.add_argument(
    '-l', '--list-names', action='store_true', dest='list_names', required=False, default=False,
    help="List the samples by their names.")

parser.add_argument(
    '-S', '--summary-output', action='store_true', dest='summary_output', required=False, default=False,
    help="Display nice summary output.")

parser.add_argument(
    '--custom-output', action='store', dest='custom_output', required=False, default=None,
    help="Schema projection.  Examples: hashes.sha1, sources, analysis.details.unicode")

args = parser.parse_args()

mwzoo.load_global_config(args.config_path)

query = {}
if args.md5 is not None:
    query['hashes.md5'] = { '$regex': args.md5 }
if args.sha1 is not None:
    query['hashes.sha1'] = { '$regex': args.sha1 }
if args.file_name is not None:
    query['names'] = { '$regex': args.file_name }
if args.mime_type is not None:
    query['analysis.details.mime_types'] = { '$regex': args.mime_type }
if args.file_type is not None:
    query['analysis.details.file_types'] = { '$regex': args.file_type }
if args.tag is not None:
    query['tags'] = { '$regex': args.tag }
if args.source is not None:
    query['sources'] = { '$regex': args.source }

fields = None
if args.custom_output is not None:
    fields = json.loads('{"' + args.custom_output + '": true, "_id": false}')

for sample in mwzoo.Database().collection.find(query, fields=fields):
    if args.summary_output is not None:
        print ','.join(sample['names'])
        print '\ttags: {0}'.format(','.join(sample['tags']))
        print '\tsources: {0}'.format(','.join(sample['sources']))
        print '\tmd5: {0}'.format(sample['hashes']['md5'])
        print '\tsha1: {0}'.format(sample['hashes']['sha1'])
        print 
    elif args.directory is not None:
        dest_file = os.path.join(args.directory, sample['names'][0])
        shutil.copyfile(sample['storage'], dest_file)
        print dest_file
    elif args.list_names:
        print ', '.join(sample['names'])
    else:
        print sample['hashes']['sha1']
