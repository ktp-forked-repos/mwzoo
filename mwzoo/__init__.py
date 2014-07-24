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
import datetime
import inspect
from subprocess import Popen, PIPE
import multiprocessing
import threading
import Queue

# twisted
from twisted.web import server, xmlrpc, resource
from twisted.internet import reactor

# mongo
from pymongo import MongoClient


# analysis tasks
import mwzoo.analysis.tasks as mwzoo_tasks

# global config
global_config = None

def load_global_config(config_path):
    global global_config
    global_config = ConfigParser.ConfigParser()

    # make sure the configuration file exists
    if not os.path.exists(config_path):
        # what about relative from the MWZOO_HOME dir?
        if (
        not os.path.isabs(config_path)
        and 'MWZOO_HOME' in os.environ 
        and os.path.exists(os.path.join(os.environ['MWZOO_HOME'], config_path))):
            config_path = os.path.join(os.environ['MWZOO_HOME'], config_path)
        else:
            # inform the user about the default configuration available
            if os.path.exists('etc/mwzoo_default.ini'):
                logging.fatal(
"*** HEY MAN *** A default configuration is available! " +  
"Type (cd etc && ln -s mwzoo_default.ini mwzoo.ini) and try again!")
            raise IOError("configuration file {0} does not exist".format(config_path))

    global_config.read(config_path)

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
    """Represents a sample file to be analyzed."""
    def __init__(self, file_name, file_content, tags, sources):
        self.file_name = file_name
        self.file_content = file_content
        self.analysis = self._generate_empty_analysis()

        # go ahead and calculate hashes
        m = hashlib.sha1()
        m.update(self.file_content)
        self.sha1_hash = m.hexdigest()

        m = hashlib.md5()
        m.update(self.file_content)
        self.md5_hash = m.hexdigest()

        m = hashlib.sha256()
        m.update(self.file_content)
        self.analysis['hashes']['sha256'] = m.hexdigest()

        # calculate file storage
        sub_dir = os.path.join(global_config.get(
            'storage', 'malware_storage_dir'), self.sha1_hash[0:3])

        self.content_path = os.path.join(sub_dir, self.sha1_hash)
        self.analysis['names'] = [ self.file_name ]
        self.tags = tags
        self.sources = sources

    @property
    def sha1_hash(self):
        """SHA1 computed hash of the content."""
        return self.analysis['hashes']['sha1']

    @sha1_hash.setter
    def sha1_hash(self, value):
        assert isinstance(value, basestring)
        assert re.match(r'^[0-9a-fA-F]{40}$', value) is not None
        self.analysis['hashes']['sha1'] = value

    @property
    def md5_hash(self):
        """MD5 computed hash of the content."""
        return self.analysis['hashes']['md5']
        
    @md5_hash.setter
    def md5_hash(self, value):
        assert isinstance(value, basestring)
        assert re.match(r'^[0-9a-fA-F]{32}$', value) is not None
        self.analysis['hashes']['md5'] = value

    @property
    def content_path(self):
        """Path to the content of the sample stored in the file system."""
        return self.analysis['storage']

    @content_path.setter
    def content_path(self, value):
        assert isinstance(value, basestring)
        self.analysis['storage'] = value

    @property
    def storage_path(self):
        """Path to directory set aside for storing extra data."""
        return '{0}-data'.format(self.content_path)

    @property
    def tags(self):
        return self.analysis['tags']

    @tags.setter
    def tags(self, value):
        assert isinstance(value, list)
        self.analysis['tags'] = value

    @property
    def sources(self):
        return self.analysis['sources']

    @sources.setter
    def sources(self, value):
        assert isinstance(value, list)
        self.analysis['sources'] = value

    def get_analysis(self, module):
        """Get an analysis result for a given module, or None if analysis does not exist."""
        for analysis in self.analysis['analysis']:
            if module == analysis['module']:
                return analysis

        return None

    def __str__(self):
        return "Sample({0})".format(self.sha1_hash)

    def _generate_empty_analysis(self):
        """Return a Dictionary initialized with all the fields the MalwareZoo supports."""
        return {
            'storage': None,
            'names': [ ] ,
            'sources': [],    # where did this file come from?
            'tags': [],
            'hashes': {
                'md5': None,
                'sha1': None,
                'sha256': None
            },
            'analysis': [
                #{
                    #'module': 'string',
                    #'date': 'some date time',
                    #'details': {
                        #'unicode': [],
                        #'ascii': []
                    #}
                #},
                #{
                    #'module': 'file_type',
                    #'date': 'some date time',
                    #'details': {
                        #'mime_types' : [ ], # file -i
                        #'file_types' : [ ], # file
                    #}
                #},
                #{
                    #'module', 'executable',
                    #'date', 'some date time',
                    #'details': {
                        #'imports': [ 
                            #{
                                #'module': string,
                                #function_name: string,
                                #ord: int
                            #} 
                        #],
                        #'sections': [ 
                            #{
                                #name: string
                                #md5 : string
                                #rva: int
                                #raw_sz: int
                                #virtual_sz: int
                            #} ]
                        #],
                        #'exports': [ 
                            #{
                                #function_name: string
                                #ord: int
                            #} ]
                        #],
                        #'packers': [],
                        #'pe_header': {
                            #'machine_build': None,
                            #'number_of_sections': None,
                            #'time_date_stamp': None,
                            #'pointer_to_symbol_table': None,
                            #'number_of_symbols': None,
                            #'size_of_optional_header': None,
                            #'characteristics': None,
                            #'optional_header': {
                                #'magic': None,
                                #'linker_version': None,
                                #'size_of_code': None,
                            #},
                        #},
                    #}
                #},
                #{
                    #'module', 'cuckoo',
                    #'date', 'some date time',
                    #'details': {
                        #'analysis': [
                        ##{
                            ##sandbox_name: {}    // ex cuckoo
                            ##sandbox_version: {} // ex 1.0.0
                            ##image_name: {}      // ex windows 7 32
                            ##c2: []          
                            ##mutexes: []
                            ##files_created: []
                            ##files_modified: []
                            ##files_deleted: []
                            ##registry_created: []
                            ##registry_modified: []
                            ##registry_deleted: []
                        ##}
                        #]
                    #}
                #},
                #{
                    #'module', 'yara',
                    #'date', 'some date time',
                    #'details': {
                        #'repository': None,     # git remote -v
                        #'commit': None,         # git log -n 1 --pretty=oneline
                        #'stdout_path': None,    # yara stdout file path
                        #'stderr_path': None     # yara stderr file path
                    #}
                #},
                #{
                    #'module', 'zlib_blocks',
                    #'date', 'some date time',
                    #'details': {
                        #'blocks': [
                            ##{
                                ##offset: int            // offset of the location in the file
                                ##content_path: string   // location of the data
                            ##}
                        #]
                    #}
                #},
                #{
                    #'module', 'exifdata',
                    #'date', 'some date time',
                    #'details': {
#
                    #}
                #},
                #{
                    #'module', 'virustotal',
                    #'date', 'some date time'
                    #'details': {
#
                    #}
                #}
            ]
        }

    def _save_content(self):
        """Save the file content to file."""

        # have we already loaded this file?
        if not os.path.exists(self.content_path):
            # malware storage is storage_dir/sha1_hash[0:3]/sha1_hash
            # does this base directory exist?
            if not os.path.exists(os.path.dirname(self.content_path)):
                os.makedirs(os.path.dirname(self.content_path))

            logging.debug("saving sample to {0}".format(self.content_path))
            with open(self.content_path, 'wb') as fp:
                fp.write(self.file_content)

        # make a spot for extra file storage for this sample
        if not os.path.exists(self.storage_path):
            try:
                os.makedirs(self.storage_path)
            except Exception, e:
                logging.error(
"unable to create storage container directory {0}: {1}".format(
    self.storage_path,
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

    def _load_analysis_tasks(self):
        """
Loads available anaysis tasks and sorts in order of dependencies.  
Returns the list of tasks as callables."""
        # load available analysis tasks
        tasks = []
        for (name, task_class) in inspect.getmembers(mwzoo_tasks):
            if inspect.isclass(task_class) and task_class.__name__.endswith('Analysis'):
                if callable(getattr(task_class, 'analyze', None)):
                    logging.debug("found task {0}".format(task_class))
                    tasks.append(task_class())

        # sort by dependencies
        index = 0
        swapped = False # since python doens't have named loops
        while index < len(tasks):
            if hasattr(tasks[index], 'depends_on'):
                for d_index in xrange(0, len(tasks[index].depends_on)):
                    for target_index in xrange(0, len(tasks)):
                        if index == target_index:
                            continue
                        if index > target_index:
                            continue
                        if tasks[target_index].__class__.__name__ == tasks[index].depends_on[d_index].__name__:
                            # is there a circular dependency?
                            if hasattr(tasks[target_index], 'depends_on') and type(tasks[index]) in tasks[target_index].depends_on:
                                raise Exception("tasks {0} and {1} depend on each other".format(
                                    tasks[index], tasks[target_index]))

                            # swap their position
                            logging.debug("swapping {0} with {1}".format(tasks[index], tasks[target_index]))
                            tasks[index], tasks[target_index] = tasks[target_index], tasks[index]

                            # sweep again
                            swapped = True
                            break

                if swapped:
                    break
            
            if swapped:
                swapped = False
                index = 0
            else:
                index += 1

        return tasks
        
    def _analyze(self):
        for task in self._load_analysis_tasks():
            try:
                result = task.analyze(self)
                self.analysis['analysis'].append({
                    'module': task.__class__.__name__,
                    'date': datetime.datetime.now(),
                    'details': result
                })
                    
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

        return self.content_path

class MalwareZoo(object):
    def __init__(self, max_process_count=0):
        self._max_process_count = max_process_count
        # incoming mwzoo.Sample objects in multiprocessing mode
        self._sample_queue = Queue.Queue()
        # processes running mwzoo.Sample.process()
        self._child_processes = []

    def process(self, sample):
        if self._max_process_count == 0:
            return sample.process()
        else:
            self._sample_queue.put(sample)
            return "queued for execution"

    def start(self):
        # are we doing multiprocessing?
        if self._max_process_count > 0:
            self._start_multiprocessing()

    def _start_multiprocessing(self):
        logging.info("starting multiprocessing")
        self._processor = threading.Thread(target=self._multiprocessing_loop, name="Malware Zoo Processor")
        self._processor.daemon = True
        self._processor.start()
        logging.info("started multiprocessing")

    def _multiprocessing_loop(self):
        while True:
            try:
                self._multiprocessing_execute()
            except Exception, e:
                logging.error(str(e))
                traceback.print_exc()
                time.sleep(1)

    def _multiprocessing_execute(self):
        # have any samples finished processing?
        dead_children = [p for p in self._child_processes if not p.is_alive()]
        for p in dead_children:
            logging.debug("removing finshed process {0}".format(p))
            self._child_processes.remove(p)

        # any available slots for processing?
        while len(self._child_processes) < self._max_process_count:
            # get the next sample to process, wait forever if you have to
            logging.debug("waiting for available sample")
            sample = self._sample_queue.get()
            assert isinstance(sample, Sample)
            logging.debug("got sample {0}".format(sample))
            # create a process to handle it
            p = multiprocessing.Process(target=sample.process, name="Malware Zoo Sample Process")
            p.daemon = True
            p.start()
            self._child_processes.append(p)

        time.sleep(0.01) # don't consume the CPU

class FileUploadHandler(xmlrpc.XMLRPC):
    def __init__(self, zoo):
        xmlrpc.XMLRPC.__init__(self)
        self.zoo = zoo

    def xmlrpc_upload(self, file_name, file_content, tags, sources):
        """Process this!"""
        return self.zoo.process(Sample(file_name, base64.b64decode(file_content), tags, sources))

class HTTPServer(resource.Resource):
    def __init__(self, zoo):
        assert isinstance(zoo, MalwareZoo)
        resource.Resource.__init__(self)
        self.putChild("upload", FileUploadHandler(zoo))

    def start(self):
        bind_host = global_config.get('networking', 'hostname')
        bind_port = global_config.getint('networking', 'port')
        reactor.listenTCP(bind_port, server.Site(self), interface=bind_host)
        logging.info("started HTTPServer on {0}:{1}".format(bind_host, bind_port))
        reactor.run()

    def stop(self):
        reactor.stop()
