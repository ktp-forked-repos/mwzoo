#!/usr/bin/env python
# vim: ts=4:sw=4:et
#
# malware zoo
#

import sys
import os, os.path
import hashlib
import time
import base64
import logging, logging.config
import traceback
import ConfigParser
import re

# twisted
from twisted.web import server, xmlrpc, resource
from twisted.internet import reactor

# mongo
from pymongo import MongoClient

# distributed tasks
#from celery import group
from multiprocessing import Process

# analysis tasks
import mwzoo.analysis.tasks as mwzoo_tasks

# global config
global_config = None

class Database(object):
    def __init__(self):
        """Connects to the mongodb specified in the config file."""
        assert global_config is not None

        self._client = MongoClient(
            host=global_config.get('mongodb', 'hostname'),
            port=global_config.getint('mongodb', 'port'))
        self._db = self._client[global_config.get('mongodb', 'database')]
        self._collection = self._db[global_config.get('mongodb', 'collection')]

    @property
    def collection(self):
        """Returns the mongodb collection used to store the analysis results."""
        return self._collection

    @property
    def database(self):
        """Returns the mongodb database used to store all mwzoo-related collections."""
        return self._db

    @property
    def connection(self):
        """Returns the mongodb connection instance."""
        return self._client

class Sample(object):
    def __init__(self, file_name, file_content, tags, sources):
        self.file_name = file_name
        self.file_content = file_content
        self.tags = tags
        self.sources = sources
        self.analysis = self._generate_empty_analysis()
        self.storage_container_dir = None

        # go ahead and calculate hashes
        m = hashlib.sha1()
        m.update(self.file_content)
        self.sha1_hash = m.hexdigest()

        m = hashlib.md5()
        m.update(self.file_content)
        self.md5_hash = m.hexdigest()

        # calculate file storage
        sub_dir = os.path.join(global_config.get('storage', 'malware_storage_dir'), self.sha1_hash[0:3])

        self.storage_path = os.path.join(sub_dir, self.sha1_hash)
        self.storage_container_dir = '{0}-data'.format(self.storage_path)
        self.analysis['names'] = [ self.file_name ]

    @property
    def sha1_hash(self):
        """SHA1 computed hash of the content."""
        return self.analysis['hashes']['sha1']

    @sha1_hash.setter
    def sha1_hash(self, value):
        assert re.match(r'^[0-9a-fA-F]{40}$', value) is not None
        self.analysis['hashes']['sha1'] = value

    @property
    def md5_hash(self):
        """MD5 computed hash of the content."""
        return self.analysis['hashes']['md5']
        
    @md5_hash.setter
    def md5_hash(self, value):
        assert re.match(r'^[0-9a-fA-F]{32}$', value) is not None
        self.analysis['hashes']['md5'] = value

    @property
    def storage_path(self):
        return self.analysis['storage']

    @storage_path.setter
    def storage_path(self, value):
        self.analysis['storage'] = value

    def __str__(self):
        return "Sample({0})".format(self.sha1_hash)

    def _generate_empty_analysis(self):
        """Return a Dictionary initialized with all the fields the MalwareZoo supports."""
        return {
            'storage': None,
            'names': [ ] ,
            'mime_types' : [ ], # file -i
            'file_types' : [ ], # file
            'hashes': {
                'md5': None,
                'sha1': None,
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
            'sources': self.sources,    # where did this file come from?
            'zlib_blocks': [
                #{
                    #offset: int            // offset of the location in the file
                    #content_path: string   // location of the data
                #}
            ]

        }

    def _save_content(self):
        """Save the file content to file."""

        # have we already loaded this file?
        if not os.path.exists(self.storage_path):
            # malware storage is storage_dir/sha1_hash[0:3]/sha1_hash
            # does this base directory exist?
            if not os.path.exists(os.path.dirname(self.storage_path)):
                os.makedirs(os.path.dirname(self.storage_path))

            logging.debug("saving sample to {0}".format(self.storage_path))
            with open(self.storage_path, 'wb') as fp:
                fp.write(self.file_content)

        # make a spot for extra file storage for this sample
        if not os.path.exists(self.storage_container_dir):
            try:
                os.makedirs(self.storage_container_dir)
            except Exception, e:
                logging.error(
"unable to create storage container directory {0}: {1}".format(
    self.storage_container_dir,
    str(e)))

    def _load_existing_analysis(self):
        """Load existing analysis results from database or initialize a new entry."""
        # do we already have an analysis of this file?
        db = Database()
        result = db.collection.find_one({'hashes.sha1': self.sha1_hash})
        if result is not None:
            self.analysis = result
            return True
        
        return False

        #if self.file_name not in self.analysis['names']:
            #logging.debug("appending file name {0} to sample {1}".format(self.file_name, sha1_hash))
            #self.analysis['names'].append(self.file_name)
        # create a new analysis for this sample

    def _analyze(self):
        # TODO use some kind of plugin architecture
        for task in [ 
            mwzoo_tasks.HashAnalysis(),
            mwzoo_tasks.YaraAnalysis(),
            mwzoo_tasks.FileTypeAnalysis(),
            mwzoo_tasks.StringAnalysis(),
            mwzoo_tasks.PEAnalysis(),
            mwzoo_tasks.ZlibAnalysis(),
            mwzoo_tasks.CuckooAnalysis()
    
        ]:
            try:
                task.analyze(self)
            except Exception, e:
                logging.error("analysis task {0} failed: {1}".format(
                    analysis.__class__.__name__, 
                    str(e)))
                traceback.print_exc()

    def _save_analysis(self):
        """Save the results of the analysis to the database."""
        db = Database()
        db.collection.save(self.analysis, manipulate=True)

    def process(self):
        """Processes a sample which analyzes the sample and then saves all results to the database or file system.
            Returns the path to the file if the save was successfull or if the file was already uploaded."""
        #
        # zooq ckane brobot
        #

        logging.info("processing sample {0}".format(self))
        self._save_content()
        if not self._load_existing_analysis():
            self._analyze()
            self._save_analysis()
        else:
            logging.info("already analyzed {0}".format(self))
            # TODO merge stuff, redo analysis, etc...

        return self.storage_path


class FileUploadHandler(xmlrpc.XMLRPC):
    def xmlrpc_upload(self, file_name, file_content, tags, sources):
        """Upload the given contents and record the included metadata."""
        return Sample(file_name, base64.b64decode(file_content), tags, sources).process()
        #return malware_zoo.save_sample(file_name, base64.b64decode(file_content))

class MalwareZoo(resource.Resource):
    def __init__(self):
        resource.Resource.__init__(self)
        self.putChild("upload", FileUploadHandler())

    def load_global_config(self, config_path):
        global global_config
        global_config = ConfigParser.ConfigParser()

        # make sure the configuration file exists
        if not os.path.exists(config_path):
            # inform the user about the default configuration available
            if os.path.exists('etc/mwzoo_default.ini'):
                logging.fatal(
"*** HEY MAN *** A default configuration is available! " +  
"Type (cd etc && ln -s mwzoo_default.ini mwzoo.ini) and try again!")
            raise IOError("configuration file {0} does not exist".format(config_path))

        global_config.read(config_path)

    def start(self):
        bind_host = global_config.get('networking', 'hostname')
        bind_port = global_config.getint('networking', 'port')
        reactor.listenTCP(bind_port, server.Site(self), interface=bind_host)
        reactor.run()

    def stop(self):
        reactor.stop()

