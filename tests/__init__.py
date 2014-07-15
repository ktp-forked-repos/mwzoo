import mwzoo
import sys
from nose.tools import raises
import unittest
import nose
from ConfigParser import ParsingError

VALID_CONFIG_PATH = 'tests/etc/valid_config.ini'
INVALID_CONFIG_PATH = 'tests/etc/invalid_config.ini'
MISSING_CONFIG_PATH = 'tests/etc/missing_config.ini' # does not exist
DEFAULT_CONFIG_PATH = 'etc/mwzoo_default.ini'

def setup_package():
    # create a special configuration for the entire malwarezoo
    pass

def teardown_package():
    pass

class config_test(unittest.TestCase):
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
            [ 'core', 'storage', 'mongodb', 'mysql' ])

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
