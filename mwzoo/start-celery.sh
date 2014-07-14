#!/bin/sh
#
# Make sure you run this from inside mwzoo base folder like:
# ./bin/start-celery.sh
#
# "celery worker" tells celery to use the worker module
# -A mwzoo_celery tells celery to load the "mwzoo_celery" application, which is just a folder name under
#                 celery-apps. You can divide your codebase up among multiple "applications" by replicating
#                 the skeleton concepts in that folder.
# --loglevel=info Set the logging level to INFO
# -c 5            Spawn 5 worker sub-processes, which work will be distributed across
#

PYTHONPATH=celery-apps celery worker -A mwzoo_celery --loglevel=info -c 5
