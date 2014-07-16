import mwzoo
import sys
import os
from nose.tools import raises, timed
import unittest
import nose
from ConfigParser import ParsingError
import atexit
import xmlrpclib
import time

VALID_CONFIG_PATH = 'tests/etc/valid_config.ini'
INVALID_CONFIG_PATH = 'tests/etc/invalid_config.ini'
MISSING_CONFIG_PATH = 'tests/etc/missing_config.ini' # does not exist
DEFAULT_CONFIG_PATH = 'etc/mwzoo_default.ini'
TEST_CONFIG_PATH = 'etc/mwzoo_test.ini'

def setup_package():
    # load the test configuration
    
    pass

def teardown_package():
    # delete the test mongodb
    
    pass

class config_test(unittest.TestCase):
    """Tests configuration files."""

    def setUp(self):
        self.zoo = mwzoo.MalwareZoo()

    def tearDown(self):
        pass

    # basic configuration file tests
    def valid_configuration_test(self):
        """Tests that a valid configuration file is loaded."""
        self.zoo.load_global_config(VALID_CONFIG_PATH)

    @raises(IOError)
    def missing_configuration_test(self):
        """Specified configuration file does not exist."""
        self.zoo.load_global_config(MISSING_CONFIG_PATH)

    @raises(ParsingError)
    def invalid_configuration_test(self):
        """Specified configuration file does not exist."""
        self.zoo.load_global_config(INVALID_CONFIG_PATH)

    # tests the default configuration file that gets shipped with the pacakge
    # these are a bit redundant but require use to think about tests
    # when the change what goes into the configuration file

    def default_config_tests(self):
        """Default config has expected section names."""
        self.zoo.load_global_config(DEFAULT_CONFIG_PATH)
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

class mwzoo_test(unittest.TestCase):
    """Tests basic MalwareZoo functionality."""

    def setUp(self):
        self.zoo = mwzoo.MalwareZoo()
        self.zoo.load_global_config(TEST_CONFIG_PATH)

        from multiprocessing import Process
        self.zoo_process = Process(target=self._mwzoo_process)
        self.zoo_process.daemon = True
        self.zoo_process.start()

    def _mwzoo_process(self):
        self.zoo.start()

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
        self.zoo = mwzoo.MalwareZoo()
        self.zoo.load_global_config(TEST_CONFIG_PATH)
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
        pass

    def tearDown(self):
        pass

    def test_save(self):
        """Validate file submission."""
        with open('/dev/urandom', 'rb') as fp:
            file_content = fp.read(1024)

        file_name = 'sample.exe'
        tags = ['tag1', 'tag2']
        sources = ['source1', 'source2']

        s = mwzoo.Sample(file_name, file_content, tags, sources)

        # make sure properties are set
        assert s.file_name == file_name
        assert s.file_content == file_content
        self.assertItemsEqual(s.tags, tags)
        self.assertItemsEqual(s.sources, sources)

        assert s.sha1_hash is not None
        assert s.md5_hash is not None
        assert s.storage_path is not None
        assert s.analysis is not None
        assert isinstance(s.analysis, dict)

        #s.save()
        
