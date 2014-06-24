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
