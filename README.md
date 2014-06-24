mwzoo
=====

Malware Zoo

Dependencies (required Ubuntu software packages)
 - python-twisted
 - python-pefile
 - python-pymongo
 - mongodb-org

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
        c2: []          
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
