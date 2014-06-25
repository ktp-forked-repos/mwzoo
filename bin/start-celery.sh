#!/bin/sh
#
# Make sure you run this from inside mwzoo base folder like:
# ./bin/start-celery.sh
PYTHONPATH=celery-apps celery worker -A mwzoo_celery --loglevel=info -c 5
