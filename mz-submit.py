#!/usr/bin/env python
# vim: ts=4:sw=4:et
import argparse
import os.path
import xmlrpclib
import base64

parser = argparse.ArgumentParser(description='MalwareZoo File Submit')
parser.add_argument(
    '-f', '--input-file', action='store', dest='input_file', required=True,
    help="The file to upload to the zoo.")
parser.add_argument(
    '-t', '--tags', action='store', nargs="*", dest='tags', required=False, default=[],
    help="Add the given tags to the sample.")
parser.add_argument(
    '-s', '--sources', action='store', nargs="*", dest='sources', required=False, default=[],
    help="Add the given sources to the sample.")
parser.add_argument(
    '-F', '--with-filename', action='store', dest='file_name', required=False, default=None,
    help="Set the file name manually (if different than the actual file name.)")
args = parser.parse_args()

s = xmlrpclib.Server('http://localhost:8081/upload')
file_contents = None
with open(args.input_file, 'rb') as fp:
    file_contents = fp.read()

print s.upload(
    args.file_name if args.file_name is not None else os.path.basename(args.input_file), 
    base64.b64encode(file_contents), 
    args.tags,
    args.sources)
