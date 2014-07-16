mwzoo
=====

Upload malware samples, run a bunch of analysis, record the output, then make it
all available for manual analysis or export to other tools.

Quick Start
 - export an environment variable called MALWARE_ZOO that points to the base directory
 - execute ./mwzoo.py # start the http server
 - execute ./submit.py -f evil.exe # submit a file for analysis
 - execute ./query.py # query based on some criteria

Dependencies (required Ubuntu software packages)
 - python-twisted
 - python-pip
 - python-pefile (install from source in extra/)
 - bitstring (sudo -E pip install bitstring)
 - requests (sudo -E pip install requests)
 - nose (sudo -E pip install nose)
 - python-pymongo
 - mongodb-org (see bin/ubuntu_install_mongodb.sh)
 - python-celery
 - rabbitmq-server
 - yara
 - ssdeep

Architecture:
 - XMLRPC interface for interacting with the zoo (requires binary content to be base64 encoded)
 - python twisted webserver accepts requests for storage and retrieval
 - files are stored on disk as-in
 - analysis tasks are kicked off for each file upload
 - extra file storage available (if it's too big for a database)
 - metadata output of analysis is stored in the various databases (configurable)
 - modular analysis architecture (work in progress)
 - unit testing written for nosetests
 
Directory Layout:
<pre>
etc                  configuration files
lib                  extra libraries
mwzoo                program files
tests                unit testing
malware              default storage directory for samples
yara                 default storage directory for yara rules
</pre>
