import mwzoo
import sys
from nose.tools import raises
from unittest import TestCase
import nose
from ConfigParser import ParsingError

VALID_CONFIG_PATH = 'tests/etc/valid_config.ini'
INVALID_CONFIG_PATH = 'tests/etc/invalid_config.ini'
MISSING_CONFIG_PATH = 'tests/etc/missing_config.ini' # does not exist

def setup_package():
    # create a special configuration for the entire malwarezoo
    pass

def teardown_package():
    pass

class mwzoo_server_test(object):
    def setup(self):
        pass

    def teardown(self):
        pass

    def valid_configuration_test(self):
        """Tests that a valid configuration file is loaded."""
        zoo = mwzoo.MalwareZoo()
        zoo.load_global_config(VALID_CONFIG_PATH)

    @raises(IOError)
    def missing_configuration_test(self):
        """Specified configuration file does not exist."""
        zoo = mwzoo.MalwareZoo()
        zoo.load_global_config(MISSING_CONFIG_PATH)

    @raises(ParsingError)
    def invalid_configuration_test(self):
        """Specified configuration file does not exist."""
        zoo = mwzoo.MalwareZoo()
        zoo.load_global_config(INVALID_CONFIG_PATH)
