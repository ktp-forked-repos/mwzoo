#!/usr/bin/env bash
#

#
# starts all required services for the malware zoo
#

# make sure we are in the malware zoo root directory
if [ -z "${MWZOO_HOME}" ]; then
    echo "missing environment variable MWZOO_HOME"
    exit 1
fi

if [ ! -d "${MWZOO_HOME}" ]; then
    echo "environment variable MWZOO_HOME references non-existing directory ${MWZOO_HOME}"
    exit 1
fi

# make cwd MWZOO_HOME
cd "${MWZOO_HOME}" || { echo "unable to cd into ${MWZOO_HOME}"; exit 1; }

# start the celery worker
#echo "starting celery"
#bin/start-celery.sh

echo "starting mwzoo web services"
#gdb --args python bin/mwzoo.py #--daemonize
python bin/mwzoo.py #--daemonize
