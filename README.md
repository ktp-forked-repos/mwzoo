mwzoo
=====

Upload malware samples, run a bunch of analysis, record the output, then make it
all available for manual analysis or export to other tools.

Installation
    sudo apt-get install git python-twisted python-pip python-pefile python-pymongo yara ssdeep
    sudo pip install bitstring
    sudo pip install requests
    sudo pip install nose
    # TODO (also install exiftool from http://www.sno.phy.queensu.ca/~phil/exiftool/)
    git clone https://github.com/unixfreak0037/mwzoo.git
    sudo ln -s /opt/mwzoo $(pwd)/mwzoo
    cd /opt/mwzoo
    # skip this if you already have mongo installed
    sudo sh bin/ubuntu_install_mongodb.sh
    cp etc/mwzoo_default.ini etc/mwzoo.ini
    # edit the etc/mwzoo.ini file to match your environment
    # the following works on Ubuntu 14.04 LTS
    sudo ln -s /opt/mwzoo/etc/profile.d/mwzoo.sh /etc/profile.d/mwzoo.sh
    source etc/profile.d/mwzoo.sh

Starting Malware Zoo
    mwzoo.py

Using Malware Zoo
    # upload a sample tagged with "zbot" and "downloader" with a source of "osint"
    mz-submit.py -f zbot.exe -t zbot -s osint
    # the mz-submit.py can be run from other systems
    # but the mz-query.py and mz-update.py commands must be run locally (for now)
    # query zoo for samples tagged with zbot and show a summary of the samples
    mz-query.py -t zbot -S
    # query zoo for samples sourced from osint and store in them a directory
    mkdir osint_samples && mz-query.py -s osint -d osint_samples
    # note that the output of mz-query is the list files stored
    mkdir osint_samples && mz-query.py -s osint -d osint_samples | while read f; run_some_command "$f"; done
    # the default output of the mz-query.py command is the expected input of the mz-update.py command
    # replace the tag of a specifc sample identified by hash with "citadel" but don't save to the database
    mz-query.py -5 7a0dfc5353ff6de7de0208a29fa2ffc9 | mz-update --update -t citadel
    # same as before, but actually save our changes to the database
    mz-query.py -5 7a0dfc5353ff6de7de0208a29fa2ffc9 | mz-update --update -t citadel --commit
    # add a tag called "rootkit" to an existing sample identified by md5
    mz-query.py -5 7a0dfc5353ff6de7de0208a29fa2ffc9 | mz-update --append -t rootkit --commit
    # get rid of all samples tagged as "b9"
    mz-query.py -t b9 | mq-update -D --commit

Currently Supported Analysis Tools and Techniques
 - ssdeep
 - yara
 - file type (uses system file command)
 - strings (uses system strings command)
 - PE analysis (uses pefile and exiftool)
 - zlib (brute force search for embedded zlib-compressed strings)
 - cuckoo (free open source sandbox analysis)

See the HACKING.txt for for docs on how to hack this thing up.

Architecture:
 - XMLRPC interface for interacting with the zoo (requires binary content to be base64 encoded)
 - python twisted webserver accepts requests for storage and retrieval
 - files are stored on disk as-in
 - analysis tasks are kicked off for each file upload
 - extra file storage available (if it's too big for a database)
 - metadata output of analysis is stored in the various databases (configurable, mongo for now)
 - modular analysis architecture
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
