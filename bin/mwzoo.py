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
import time
import base64
import logging, logging.config
import traceback

# twisted
from twisted.web import server, xmlrpc, resource
from twisted.internet import reactor

# mongo
from pymongo import MongoClient

# distributed tasks
#from celery import group
from multiprocessing import Process

# analysis tasks
import analysis.tasks as mwzoo_tasks

# global config
global_config = None

class Sample(object):
    def __init__(self, file_name, file_content, tags):
        self.file_name = file_name
        self.file_content = file_content
        self.tags = tags
        self.storage_container_dir = None

    def save(self):
        """Saves a sample to the database, which begins processing on it.  
            Returns the path to the file if the save was successfull or if the file was already uploaded."""

        logging.info("adding sample {0}".format(self.file_name))
        
        # calculate the sha1 hash of the file
        m = hashlib.sha1()
        m.update(self.file_content)
        sha1_hash = m.hexdigest()
        logging.debug("sample {0} has sha1_hash {1}".format(self.file_name, sha1_hash))

        sub_dir = os.path.join(global_config.get('storage', 'malware_storage_dir'), sha1_hash[0:3])
        if not os.path.exists(sub_dir):
            os.mkdir(sub_dir)

        target_file = os.path.join(sub_dir, sha1_hash)

        # have we already loaded this file?
        if not os.path.exists(target_file):
            # save the file to disk
            with open(target_file, 'wb') as fp:
                fp.write(self.file_content)
        else:
            logging.debug("sample {0} already exists".format(sha1_hash))

        # do we already have an analysis of this file?
        client = MongoClient()
        db = client['mwzoo']
        collection = db['analysis']

        analysis = collection.find_one({'hashes.sha1': sha1_hash})

        # have we seen this sample before?
        if analysis is not None:
            # have we seen this sample with this file name before?
            if self.file_name not in analysis['names']:
                logging.debug("appending file name {0} to sample {1}".format(self.file_name, sha1_hash))
                analysis['names'].append(self.file_name)
        else:
            # create a new analysis for this sample
            collection.insert({
                'storage': target_file,
                'names': [ self.file_name ] ,
                'mime_types' : [ ], # file -i
                'file_types' : [ ], # file
                'hashes': {
                    'md5': None,
                    'sha1': sha1_hash,
                    'sha256': None,
                    'pehash': None,
                    'imphash': None,
                    'ssdeep': None
                },
                'strings': {
                    'unicode': [],
                    'ascii': []
                },
                'imports': [ 
                    #{
                        #'module': string,
                        #function_name: string,
                        #ord: int
                    #} 
                ],
                'sections': [ 
                    #{
                        #name: string
                        #md5 : string
                        #rva: int
                        #raw_sz: int
                        #virtual_sz: int
                    #} ]
                ],
                'exports': [ 
                    #{
                        #function_name: string
                        #ord: int
                    #} ]
                ],
                'packers': [],
                'street_names': [
                    #{
                        #vendor: {}
                        #streetname: {}
                    #}]
                ],
                'pe_header': {
                    'machine_build': None,
                    'number_of_sections': None,
                    'time_date_stamp': None,
                    'pointer_to_symbol_table': None,
                    'number_of_symbols': None,
                    'size_of_optional_header': None,
                    'characteristics': None,
                    'optional_header': {
                        'magic': None,
                        'linker_version': None,
                        'size_of_code': None,
                    },
                },
                'tags': self.tags,
                'behavior': [
                    #{
                        #sandbox_name: {}    // ex cuckoo
                        #sandbox_version: {} // ex 1.0.0
                        #image_name: {}      // ex windows 7 32
                        #c2: []          
                        #mutexes: []
                        #files_created: []
                        #files_modified: []
                        #files_deleted: []
                        #registry_created: []
                        #registry_modified: []
                        #registry_deleted: []
                    #]}
                ],
                'yara': {
                    'repository': None,     # git remote -v
                    'commit': None,         # git log -n 1 --pretty=oneline
                    'stdout_path': None,    # yara stdout file path
                    'stderr_path': None     # yara stderr file path
                },
                'exifdata': {},
                'source': [],      # where did this file come from?
                'zlib_blocks': [
                    #{
                        #offset: int            // offset of the location in the file
                        #content_path: string   // location of the data
                    #}
                ]
            })

            # then get it back out
            analysis = collection.find_one({'hashes.sha1': sha1_hash})

        #
        # (eventually use celery to distribute the tasks)
        #

        # TODO limit the total number of concurrent processes
        # tried to use a Pool but couldn't get it to work
        #p = Process(target=self.process_sample, args=(analysis,))
        #p.start()

        # make a spot for extra file storage for this sample
        self.storage_container_dir = target_file + "-data"
        if not os.path.exists(self.storage_container_dir):
            try:
                os.makedirs(self.storage_container_dir)
            except Exception, e:
                logging.error(
"unable to create storage container directory {0}: {1}".format(
    self.storage_container_dir,
    str(e)))

        self.process_sample(analysis)

        return target_file

    def process_sample(self, analysis):
        for task in [ 
            mwzoo_tasks.HashAnalysis(),
            mwzoo_tasks.YaraAnalysis(),
            mwzoo_tasks.FileTypeAnalysis(),
            mwzoo_tasks.StringAnalysis(),
            mwzoo_tasks.PEAnalysis(),
            mwzoo_tasks.ZlibAnalysis()
    
        ]:
            try:
                task.analyze(self, analysis)
            except Exception, e:
                logging.error("analysis task {0} failed: {1}".format(
                    analysis.__class__.__name__, 
                    str(e)))
                traceback.print_exc()

        # save the results to the database!
        client = MongoClient()
        db = client['mwzoo']
        collection = db['analysis']
        collection.save(analysis)

class MalwareZoo(resource.Resource):
    def __init__(self):
        resource.Resource.__init__(self)

class FileUploadHandler(xmlrpc.XMLRPC):
    def xmlrpc_upload(self, file_name, file_content, tags):
        """Upload the given contents and record the included metadata."""
        return Sample(file_name, base64.b64decode(file_content), tags).save()
        #return malware_zoo.save_sample(file_name, base64.b64decode(file_content))

if __name__ == '__main__':
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

    global_config = ConfigParser.ConfigParser()
    global_config.read(args.config_path)

    logging.debug("starting malware zoo")
    malware_zoo = MalwareZoo()
    malware_zoo.putChild("upload", FileUploadHandler())
    reactor.listenTCP(8081, server.Site(malware_zoo))
    reactor.run()
