#!/usr/bin/python
from __future__ import absolute_import
from celery import Celery

celery = Celery('mwzoo_celery.celery', broker='amqp://', backend='amqp://',
                include=['mwzoo_celery.tasks'])

if __name__ == '__main__':
    celery.start()

