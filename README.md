mwzoo
=====

Malware Zoo

Quick Start
 - export an environment variable called MALWARE_ZOO that points to the base directory
 - execute bin/start-mwzoo.sh

Dependencies (required Ubuntu software packages)
 - python-twisted
 - python-pip
 - python-pefile (install from source in extra/)
 - bitstring (sudo -E pip install bitstring)
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
 - analysis tasks are kicked off as celery tasks
 - FILE output of analysis is stored in the scan/ folder
 - metadata output of analysis is stored in the various databases (configurable)

Starting celery:
 - You want to run all the scripts from inside the top-level project folder
 - sh ./bin/start-celery.sh -> Runs celery in the foreground, loads apps
 - python ./bin/celery-yara.py FILENAME1 /PATH/TO/FILE/2 -> distribute work, results will go into ./scans/
 - Rather than pass data via messages (returns / args) using celery, I found it preferrable to write files to disk as the "outcome" for a celery task, and then later dependent tasks expect it to exist if the process succeeded. Doing this early can help prevent you from DoSing celery later on in life.
 
Directory Layout:
<pre>
analysis-scripts     TODO
bin                  program executables and scripts
celery-apps          celery task modules
etc                  malware zoo configuration files
lib                  extra libraries
malware              default storage directory for samples
scans                default storage directory for task output (?)
yara                 default storage directory for yara rules
</pre>

Ideas:
 - Use celery to distribute tasks
 - Write simple interface definition for tasks
 - Store analysis data in folders
 - Sync data to be used for relational purposes in MySQL or SQLITE3
 - Make interfacing for CRITs
 - Don't necessarily bother w/ cuckoo... maybe just write our own lightweight automated-sandbox (again)...
   - Or just write parsers against cuckoo's output to greatly downsize the json files
   - Perhaps we can create automated sandbox configuration scripts so when someone sets up a sandbox they only need to install the OS, install packages, then run setup script.
 - Make sandbox configurable or "polymorphic" so malware is unable to look for particular files to know it is running in a sandbox.
 - Cuckoo is annoying and finicky and wants too much to become a "complete, do all things, solution"

JSON sample metadata format:
```
{
    file: {
        name: [] 
        hashes {
        md5: {}
        sha1: {}
        sha256: {}
        pehash: {}
        imphash: {}
    }
    strings: {
        unicode: []
        ascii: []
    }
    imports: [ {
        module: {}
        function_name: {}
        ord: {}
    } ]
    sections: [ {
        name: {} 
        md5 : {}
        file_offset: {}
        rva: {}
        raw_sz: {}
        virtual_sz: {}
    } ]
    exports: [ {
        function_name: {}
        ord: {}
        
    } ]
    packers: []
    street_names: [{
        vendor: {}
        streetname: {}
    }]
    pe_header:{
        machine_build:{}
        number_of_sections: {}
        time_date_stamp: {}
        pointer_to_symbol_table: {}
        number_of_symbols: {}
        size_of_optional_header: {}
        characteristics: {}
        optional_header: {
            magic: {}
            linker_version: {}
            size_of_code: {}
            …..
            //this goes and goes
        }
    }
    tags:[]
    behavior: [{
        sandbox_name: {}    // ex cuckoo
        sandbox_version: {} // ex 1.0.0
        image_name: {}      // ex windows 7 32
        c2: [{'address': 'blah.com', 'port': 8080}]          
        mutexes: []
        files_created: []
        files_modified: []
        files_deleted: []
        registry_created: []
        registry_modified: []
        registry_deleted: []
    ]}
    exifdata: {
        
    }
    source: {}      // where did this file come from?
    } // end file
}
```
