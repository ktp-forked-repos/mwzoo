#!/usr/bin/env python
# vim: ts=4:sw=4:et
import argparse
import os.path
import shutil

# mongo
from pymongo import MongoClient

parser = argparse.ArgumentParser(description='Malware Zoo Sample Query')

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


args = parser.parse_args()

# query the database
client = MongoClient()
db = client['mwzoo']
collection = db['analysis']

query = {}
if args.md5 is not None:
    query['hashes.md5'] = { '$regex': args.md5 }
if args.sha1 is not None:
    query['hashes.sha1'] = { '$regex': args.sha1 }
if args.file_name is not None:
    query['names'] = { '$regex': args.file_name }
if args.mime_type is not None:
    query['mime_types'] = { '$regex': args.mime_type }
if args.file_type is not None:
    query['file_types'] = { '$regex': args.file_type }
if args.tag is not None:
    query['tags'] = { '$regex': args.tag }

for sample in collection.find(query):
    if args.directory is not None:
        dest_file = os.path.join(args.directory, sample['names'][0])
        shutil.copyfile(sample['storage'], dest_file)
        print dest_file
    else:
        print ', '.join(sample['names'])
