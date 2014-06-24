#!/usr/bin/env python
# vim: ts=4:sw=4:et
#
# malware zoo
#

import argparse
import sys
import os, os.path
import ConfigParser
import hashlib

from twisted.web import server, xmlrpc, resource
from twisted.internet import reactor

# global malware zoo pointer
malware_zoo = None

class MalwareZoo(resource.Resource):
    def load_config(self, config_path):
        """Load configuration settings from config_path"""
        self.config = ConfigParser.ConfigParser()
        self.config.read(config_path)

        # sanity check configuration settings
        self.malware_storage_dir = self.config.get('storage', 'malware_storage_dir', None)
        if self.malware_storage_dir is None:
            sys.stderr.write('missing configuration option malware_storage_dir in section storage\n')
            sys.exit(1)

        if not os.path.exists(self.malware_storage_dir):
            sys.stderr.write('malware storage directory {0} does not exist\n'.format(self.malware_storage_dir))
            sys.exit(1)

    def save_sample(self, file_name, file_content):
        """Saves a sample to the database, which begins processing on it.  
            Returns the path to the file if the save was successfull, None if the file was already uploaded."""
        
        # calculate the sha1 hash of the file
        m = hashlib.sha1()
        m.update(file_content)
        sha1_hash = m.hexdigest()
        sub_dir = os.path.join(self.malware_storage_dir, sha1_hash[0:3])
        if not os.path.exists(sub_dir):
            os.mkdir(sub_dir)

        target_file = os.path.join(sub_dir, sha1_hash)

        # have we already loaded this file?
        if os.path.exists(target_file):
            return None

        # save the file to disk
        with open(target_file, 'wb') as fp:
            fp.write(file_content)
    
        # save metadata to the database
        # TODO

        return target_file
        
        
class FileUploadHandler(xmlrpc.XMLRPC):

    def xmlrpc_upload(self, file_name, file_content):
        """Upload the given contents and record the included metadata."""
        return malware_zoo.save_sample(file_name, file_content)
    
    #def render_GET(self, request):
        #request.setHeader("content-type", "text/plain")
        #return "sup bro"

    #def render_POST(self, request):
        #if 'file' not in request.args:
            #request.setResponseCode(500)
            #return 'missing file argument'

        #return 'sent {0} bytes'.format(len(request.args['file'][0]))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MalwareZoo')
    parser.add_argument(
        '-c', '--config-path', action='store', dest='config_path', default='etc/mwzoo.ini', required=False,
        help='Path to configuration file for the malware zoo.')
    args = parser.parse_args()

    if not os.path.exists(args.config_path):
        sys.stderr.write('missing configuration file {0}\n'.format(args.config_path))
        sys.exit(1)

    malware_zoo = MalwareZoo()
    malware_zoo.putChild("upload", FileUploadHandler())
    
    # load the malware zoo configuration
    malware_zoo.load_config(args.config_path)
    
    reactor.listenTCP(8081, server.Site(malware_zoo))
    reactor.run()
