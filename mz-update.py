#!/usr/bin/env python
# vim: ts=4:sw=4:et
import argparse
import mwzoo
import sys

parser = argparse.ArgumentParser(description='Malware Zoo Update')

# standard options TODO - refactor
parser.add_argument(
    '--mwzoo-home', action='store', dest='mwzoo_home', default=None, required=False,
    help='Path to the base installation directory of the malware zoo.  This overrides MWZOO_HOME environment variable, if set.')
parser.add_argument(
    '-c', '--config-path', action='store', dest='config_path', default='etc/mwzoo.ini', required=False,
    help='Path to configuration file for the malware zoo.')

# update options
parser.add_argument(
    '-a', '--append', action='store_true', dest='append', required=False, default=False,
    help="Append new values to existing values.")
parser.add_argument(
    '-u', '--update', action='store_true', dest='update', required=False, default=False,
    help="Update (replace) existing values with new values.")
parser.add_argument(
    '-d', '--delete', action='store_true', dest='delete', required=False, default=False,
    help="Delete given values from the sample.")
parser.add_argument(
    '-D', '--delete-sample', action='store_true', dest='delete_sample', required=False, default=False,
    help="Delete given sample entirely from the database.")

# update values
parser.add_argument(
    '-t', '--tags', action='store', nargs='*', dest='tags', required=False, default=[],
    help="")
parser.add_argument(
    '-s', '--sources', action='store', nargs='*', dest='sources', required=False, default=[],
    help="")

# committer
parser.add_argument(
    '--commit', action='store_true', dest='commit', required=False, default=False,
    help="Commit changes to the database.  This option is required to make actual changes to the data.")

args = parser.parse_args()

mwzoo.load_global_config(args.config_path)
db = mwzoo.Database()
_ids = []

for sha1 in sys.stdin:
    sha1 = sha1.strip()
    result = db.collection.find_one({'hashes.sha1': sha1})
    assert result is not None
    
    if args.append:
        if len(args.tags) > 0:
            result['tags'].extend(list(set(args.tags)))
        if len(args.sources) > 0:
            result['sources'].extend(list(set(args.sources)))
    elif args.update:
        result['tags'] = list(set(args.tags))
        result['sources'] = list(set(args.sources))
    elif args.delete:
        for tag in args.tags:
            if tag in result['tags']:
                result['tags'].remove(tag)
        for source in args.sources:
            if source in result['sources']:
                result['sources'].remove(source)
    elif args.delete_sample:
        pass
    else:
        sys.stderr.write('missing --append, --update, --delete or --delete-sample options\n')
        sys.exit(1)

    if args.delete_sample:
        print "deleting sample {0}".format(sha1)
        if args.commit:
            #print db.collection.remove(result)
            # see https://groups.google.com/forum/#!topic/mongodb-user/twffSJ04D5o
            db.collection.remove({'_id': result['_id']})
            print "deleted sample {0}".format(sha1)
    else:
        print "saving changes to {0}".format(sha1)
        if args.commit:
            db.collection.save(result)
            print "saved changes to {0}".format(sha1)
