import mwzoo
import sys
import os, os.path
from nose.tools import raises, timed
import unittest
import nose
from ConfigParser import ParsingError
import atexit
import xmlrpclib
import time
from subprocess import Popen

VALID_CONFIG_PATH = 'tests/etc/valid_config.ini'
INVALID_CONFIG_PATH = 'tests/etc/invalid_config.ini'
MISSING_CONFIG_PATH = 'tests/etc/missing_config.ini' # does not exist
DEFAULT_CONFIG_PATH = 'etc/mwzoo_default.ini'
TEST_CONFIG_PATH = 'etc/mwzoo_test.ini'

def setup_package():
    # if we don't specify a directory then we default to cwd
    if 'MWZOO_HOME' not in os.environ:
        os.environ['MWZOO_HOME'] = '.'

    try:
        os.chdir(os.environ['MWZOO_HOME'])
    except Exception, e:
        raise Exception(
            "unable to change working directory to {0}: {1}".format(
            os.environ['MWZOO_HOME']))
    
    # load the test configuration
    mwzoo.load_global_config(TEST_CONFIG_PATH)

def teardown_package():
    # delete the test mongodb
    pass

class config_test(unittest.TestCase):
    """Tests configuration files."""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    # basic configuration file tests
    def valid_configuration_test(self):
        """Tests that a valid configuration file is loaded."""
        mwzoo.load_global_config(VALID_CONFIG_PATH)

    @raises(IOError)
    def missing_configuration_test(self):
        """Specified configuration file does not exist."""
        mwzoo.load_global_config(MISSING_CONFIG_PATH)

    @raises(ParsingError)
    def invalid_configuration_test(self):
        """Specified configuration file does not exist."""
        mwzoo.load_global_config(INVALID_CONFIG_PATH)

    # tests the default configuration file that gets shipped with the pacakge
    # these are a bit redundant but require use to think about tests
    # when the change what goes into the configuration file

    def default_config_tests(self):
        """Default config has expected section names."""
        mwzoo.load_global_config(DEFAULT_CONFIG_PATH)
        # test that these sections exist
        self.assertItemsEqual(mwzoo.global_config.sections(),
            [ 'networking', 'storage', 'mongodb', 'mysql' ])

        # just test that these settings exist
        assert mwzoo.global_config.get(
            'storage', 'malware_storage_dir', None) is not None

        assert mwzoo.global_config.get(
            'mongodb', 'hostname', None) is not None
        assert mwzoo.global_config.get(
            'mongodb', 'database', None) is not None
        assert mwzoo.global_config.get(
            'mongodb', 'collection', None) is not None
        assert mwzoo.global_config.get(
            'mongodb', 'port', None) is not None

        assert mwzoo.global_config.get(
            'mysql', 'hostname', None) is not None
        assert mwzoo.global_config.get(
            'mysql', 'database', None) is not None
        assert mwzoo.global_config.get(
            'mysql', 'user', None) is not None
        assert mwzoo.global_config.get(
            'mysql', 'password', None) is not None

class http_server_test(unittest.TestCase):
    """Tests basic http server functionality."""

    def setUp(self):
        # load the test configuration
        mwzoo.load_global_config(TEST_CONFIG_PATH)

        self.http_server = mwzoo.HTTPServer()

        from multiprocessing import Process
        self.server_process = Process(target=self._server_process)
        self.server_process.daemon = True
        self.server_process.start()

    def _server_process(self):
        self.http_server.start()

    def tearDown(self):
        pass

    def startup_test(self):
        """Ensure malware starts up and listens on the given port."""
        import socket, time

        mwzoo_host = mwzoo.global_config.get('networking', 'hostname')
        mwzoo_port = mwzoo.global_config.getint('networking', 'port')
        
        # try to connect to the local port
        for x in xrange(3):
            s = socket.socket()
            try:
                s.connect(('localhost', mwzoo_port))
                s.close()
                return
            except Exception, e:
                pass

            time.sleep(1)

        raise Exception(
"Unable to connect to malware zoo {0}:{1}".format(mwzoo_host, mwzoo_port))

class database_test(unittest.TestCase):
    def setUp(self):
        # load the test configuration
        mwzoo.load_global_config(TEST_CONFIG_PATH)

        self.db = mwzoo.Database()

    def connection_test(self):
        """Test Database object connectivity."""
        assert self.db.connection.alive()

    def property_test(self):
        """Test expected properties of Database object."""
        assert hasattr(self.db, 'connection')
        assert hasattr(self.db, 'database')
        assert hasattr(self.db, 'collection')

    def crud_test(self):
        """Test basic create, update, delete on mongodb."""
        test_document = { 'test': 'document' }
        self.db.collection.remove(None, multi=True)
        self.db.collection.insert(test_document, manipulate=True)

        assert '_id' in test_document
        
        result = self.db.collection.find({'_id': test_document['_id']})
        assert result is not None
        assert result.count() == 1
        assert 'test' in result[0]

        result = self.db.collection.find_one({'_id': test_document['_id']})
        assert result is not None
        assert result['_id'] == test_document['_id']

        result['test'] = 'world'
        self.db.collection.save(result)
        result = self.db.collection.find_one({'_id': test_document['_id']})
        assert result['test'] == 'world'

        self.db.collection.remove(None, multi=True)
        result = self.db.collection.find({})
        assert result.count() == 0

class sample_test(unittest.TestCase):
    """Tests the Sample class."""
    def setUp(self):
        # load the test configuration
        mwzoo.load_global_config(TEST_CONFIG_PATH)

        # generate some random data for file content
        with open('/dev/urandom', 'rb') as fp:
            self.file_content = fp.read(1024)

        self.file_name = 'sample.exe'
        self.tags = ['tag1', 'tag2']
        self.sources = ['source1', 'source2']
        self.sample = mwzoo.Sample(
            self.file_name, self.file_content, self.tags, self.sources)

    def tearDown(self):
        pass

    def test_constructor(self):
        """Validate Sample constructor."""
        # make sure properties are set
        assert self.sample.file_name == self.file_name
        assert self.sample.file_content == self.file_content
        self.assertItemsEqual(self.sample.tags, self.tags)
        self.assertItemsEqual(self.sample.sources, self.sources)

        assert self.sample.sha1_hash is not None
        assert self.sample.md5_hash is not None
        assert self.sample.storage_path is not None
        assert self.sample.analysis is not None
        assert isinstance(self.sample.analysis, dict)

    #def test_save(self):
        #"""Validate file submission."""
        #self.sample._save_content()
        #with open(self.
        
