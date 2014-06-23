#!/usr/bin/env python
# vim: ts=4:sw=4:et

import xmlrpclib
s = xmlrpclib.Server('http://localhost:8081/upload')
print s.upload("MY FILE NAME", "EVIL APT MALZ")
