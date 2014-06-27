#!/usr/bin/env python
# vim: ts=4:sw=4:et
import argparse
import os.path
import xmlrpclib
import base64

parser = argparse.ArgumentParser(description='MalwareZoo File Submit')
parser.add_argument(
    '-f', '--input-file', action='store', dest='input_file', required=True,
    help='The file to upload to the zoo.')
#parser.add_argument(
    #'-n', '--file-name', action='store', dest='file_name', required=True,
    #help='The name of the file (ex: svchost.exe)')
args = parser.parse_args()

s = xmlrpclib.Server('http://localhost:8081/upload')
file_contents = None
with open(args.input_file, 'rb') as fp:
    file_contents = fp.read()

print s.upload(os.path.basename(args.input_file), base64.b64encode(file_contents))
