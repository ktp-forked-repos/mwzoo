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
from subprocess import Popen, PIPE
import traceback
import threading
import tempfile
import shutil

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

        self.http_server = mwzoo.HTTPServer(mwzoo.MalwareZoo())

        from multiprocessing import Process
        self.server_process = Process(target=self._server_process)
        self.server_process.daemon = True
        self.server_process.start()

    def _server_process(self):
        self.http_server.start()

    def tearDown(self):
        self.server_process.terminate()
        self.server_process.join()

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

    def _clear_database(self):
        mwzoo.Database().collection.remove(None, multi=True)

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
        assert self.sample.content_path is not None
        assert self.sample.analysis is not None
        assert isinstance(self.sample.analysis, dict)

    def test_save_content(self):
        """Testing saving file content."""
        self.sample._save_content()
        with open(self.sample.content_path, 'rb') as fp:
            saved_content = fp.read()

        assert saved_content == self.sample.file_content
        assert os.path.exists(self.sample.storage_path)
        assert os.path.isdir(self.sample.storage_path)

    def test_analysis_database(self):
        """Testing loading and saving analysis from database."""
        self._clear_database()
        self.sample._save_content()
        result = self.sample._load_existing_analysis()
        assert not result
        self.sample._save_analysis()
        result = self.sample._load_existing_analysis()
        assert result

    def test_analysis(self):
        """Test the core analysis call."""
        self._clear_database()
        self.sample.process()

    def test_module_loading(self):
        """Test loading of modules."""
        tasks = self.sample._load_analysis_tasks()
        assert len(tasks) > 0
        for task in tasks:
            assert isinstance(task, mwzoo.analysis.tasks.AnalysisTask)

    # TODO need to figure this one out
    #@raises(Exception)
    #def test_module_circular_dependency(self):
        #"""Test circular dependency detection in analysis task loading."""
        #from mwzoo.analysis.tasks import AnalysisTask
        #class mwzoo.analysis.tasks.TestClassA(AnalysisTask):
            #def analyze(self, sample):
                #pass

class utility_test(unittest.TestCase):
    """Tests the mz-*.py utilities."""
    def setUp(self):
        # load the test configuration
        mwzoo.load_global_config(TEST_CONFIG_PATH)

        self.zoo_process = None
        self.zoo_stdout = ''
        self.zoo_stdout_thread = None
        self.zoo_stderr = ''
        self.zoo_stderr_thread = None
        self._clear_database()
        self._start_malware_zoo()

        self.zoo_started = threading.Event()
        self.temp_dir = tempfile.mkdtemp()

    def _clear_database(self):
        mwzoo.Database().collection.remove(None, multi=True)

    def _start_malware_zoo(self):
        # start the malware zoo server on the side
        self.zoo_process = Popen(['python', 'mwzoo.py', '-c', 'etc/mwzoo_test.ini'], stdout=PIPE, stderr=PIPE)

        self.zoo_stdout_thread = threading.Thread(target=self._read_zoo_stdout, name="_read_zoo_stdout")
        self.zoo_stdout_thread.start()

        self.zoo_stderr_thread = threading.Thread(target=self._read_zoo_stderr, name="_read_zoo_stderr")
        self.zoo_stderr_thread.start()

    # TODO refactor :)
    def _read_zoo_stdout(self):
        while True:
            try:
                line = self.zoo_process.stdout.readline()
                if line == '':
                    return

                # watch for the http server to start
                if 'started HTTPServer on' in line:
                    self.zoo_started.set()

                self.zoo_stdout += line
                print "zoo stdout: {0}".format(line.strip())
            except Exception, e:
                traceback.print_exc()
                return

    def _read_zoo_stderr(self):
        while True:
            try:
                line = self.zoo_process.stderr.readline()
                if line == '':
                    return

                self.zoo_stderr += line
                print "zoo stderr: {0}".format(line.strip())
            except Exception, e:
                traceback.print_exc()
                return

    def tearDown(self):
        try:
            if self.zoo_process is not None:
                print "killing zoo process"
                self.zoo_process.terminate()
                self.zoo_process.wait()
        except Exception, e:
            traceback.print_exc()

        if self.zoo_stdout_thread is not None:
            print "waiting for zoo stdout thread..."
            self.zoo_stdout_thread.join()

        if self.zoo_stderr_thread is not None:
            print "waiting for zoo stderr thread..."
            self.zoo_stderr_thread.join()

        shutil.rmtree(self.temp_dir)

    def test_utilities(self):
        # load the test configuration
        mwzoo.load_global_config(TEST_CONFIG_PATH)

        # wait for the http server to start
        self.zoo_started.wait(5)

        # submit the example file
        submit_process = Popen([
'python', 'mz-submit.py', '--remote-host', 'localhost:8082', 
'-f', 'tests/data/HelloWorld.exe', 
'-t', 'tag1', 'tag2', 
'-s', 'source1', 'source2'], stdout=PIPE)
        (stdout, stderr) = submit_process.communicate()
        assert submit_process.returncode == 0
        assert stdout.strip() == ".malware_test/3f8/3f896076056ef80ca508daf1317bbd22bd29de3e"

        # test default output
        query_process = Popen(['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini'], stdout=PIPE)
        (stdout, stderr) = query_process.communicate()
        assert query_process.returncode == 0
        # expecting a single line of output
        assert len(stdout.split('\n')) == 2 # technically two including the new line
        # expecting sha1 hash
        assert stdout.strip() == '3f896076056ef80ca508daf1317bbd22bd29de3e'

        # test summary output
        query_process = Popen(['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-S'], stdout=PIPE)
        (stdout, stderr) = query_process.communicate()
        assert query_process.returncode == 0

        # look for the sha1
        assert '3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout
        # look for the md5
        assert '5d2c773d17866b0135feda1ef50b573a' in stdout
        # look for the two tags
        assert 'tag1' in stdout
        assert 'tag2' in stdout
        # look for the two sources
        assert 'source1' in stdout
        assert 'source2' in stdout

        # test file extraction
        query_process = Popen(['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-d', self.temp_dir], stdout=PIPE)
        (stdout, stderr) = query_process.communicate()
        assert query_process.returncode == 0
        assert stdout.strip() == os.path.join(self.temp_dir, 'HelloWorld.exe')
        # make sure it pulled the right file
        cmp_process = Popen(['cmp', os.path.join(self.temp_dir, 'HelloWorld.exe'), 'tests/data/HelloWorld.exe'])
        cmp_process.wait()
        assert cmp_process.returncode == 0

        # test query by various criteria
        for argument_configuration in [
            ['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-5', '5d2c773d17866b0135feda1ef50b573a'],
            ['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-1', '3f896076056ef80ca508daf1317bbd22bd29de3e'],
            ['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-n', 'HelloWorld.exe'],
            ['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-t', 'tag1'],
            ['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-t', 'tag2'],
            ['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-s', 'source1'],
            ['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-s', 'source2']]:
            
            query_process = Popen(argument_configuration, stdout=PIPE)
            (stdout, stderr) = query_process.communicate()
            assert query_process.returncode == 0
            assert stdout.strip() == '3f896076056ef80ca508daf1317bbd22bd29de3e'

        # test --commit
        update_process = Popen(['python', 'mz-update.py', '-c', 'etc/mwzoo_test.ini', '--update', '-t', 'tag3', '-s', 'source3'], stdin=PIPE, stdout=PIPE)
        update_process.stdin.write('3f896076056ef80ca508daf1317bbd22bd29de3e\n')
        (stdout, stderr) = update_process.communicate()
        assert query_process.returncode == 0
        assert 'saving changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout
        assert 'saved changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' not in stdout

        # test update
        update_process = Popen(['python', 'mz-update.py', '-c', 'etc/mwzoo_test.ini', '--update', '-t', 'tag3', '-s', 'source3', '--commit'], stdin=PIPE, stdout=PIPE)
        update_process.stdin.write('3f896076056ef80ca508daf1317bbd22bd29de3e\n')
        (stdout, stderr) = update_process.communicate()
        assert query_process.returncode == 0
        assert 'saving changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout
        assert 'saved changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout

        # verify updates
        query_process = Popen(['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-S'], stdout=PIPE)
        (stdout, stderr) = query_process.communicate()
        assert query_process.returncode == 0

        # look for the new tag
        assert 'tag3' in stdout
        assert 'source3' in stdout

        # make sure old tags and sources are gone
        assert 'tag1' not in stdout
        assert 'tag2' not in stdout
        assert 'source1' not in stdout
        assert 'source2' not in stdout

        # test append
        update_process = Popen(['python', 'mz-update.py', '-c', 'etc/mwzoo_test.ini', '--append', '-t', 'tag4', '-s', 'source4', '--commit'], stdin=PIPE, stdout=PIPE)
        update_process.stdin.write('3f896076056ef80ca508daf1317bbd22bd29de3e\n')
        (stdout, stderr) = update_process.communicate()
        assert query_process.returncode == 0
        assert 'saving changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout
        assert 'saved changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout

        # verify updates
        query_process = Popen(['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-S'], stdout=PIPE)
        (stdout, stderr) = query_process.communicate()
        assert query_process.returncode == 0

        # look for the old and new tag
        assert 'tag3' in stdout
        assert 'tag4' in stdout
        assert 'source3' in stdout
        assert 'source4' in stdout

        # test delete
        update_process = Popen(['python', 'mz-update.py', '-c', 'etc/mwzoo_test.ini', '--delete', '-t', 'tag3', '-s', 'source3', '--commit'], stdin=PIPE, stdout=PIPE)
        update_process.stdin.write('3f896076056ef80ca508daf1317bbd22bd29de3e\n')
        (stdout, stderr) = update_process.communicate()
        assert query_process.returncode == 0
        assert 'saving changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout
        assert 'saved changes to 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout

        # verify updates
        query_process = Popen(['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-S'], stdout=PIPE)
        (stdout, stderr) = query_process.communicate()
        assert query_process.returncode == 0

        assert 'tag3' not in stdout
        assert 'tag4' in stdout
        assert 'source3' not in stdout
        assert 'source4' in stdout
        
        # test delete sample    
        update_process = Popen(['python', 'mz-update.py', '-c', 'etc/mwzoo_test.ini', '-D', '--commit'], stdin=PIPE, stdout=PIPE)
        update_process.stdin.write('3f896076056ef80ca508daf1317bbd22bd29de3e\n')
        (stdout, stderr) = update_process.communicate()
        assert query_process.returncode == 0
        assert 'deleting sample 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout
        assert 'deleted sample 3f896076056ef80ca508daf1317bbd22bd29de3e' in stdout

        # verify delete
        query_process = Popen(['python', 'mz-query.py', '-c', 'etc/mwzoo_test.ini', '-S'], stdout=PIPE)
        (stdout, stderr) = query_process.communicate()
        assert query_process.returncode == 0
        assert stdout.strip() == ''
