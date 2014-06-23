#!/usr/bin/env python
# vim: ts=4:sw=4:et
#
# malware zoo
#

from twisted.web import server, resource
from twisted.internet import reactor

class HelloResource(resource.Resource):
    isLeaf = True
    numberRequests = 0
    
    def render_GET(self, request):
        self.numberRequests += 1
        request.setHeader("content-type", "text/plain")
        return "I am request #" + str(self.numberRequests) + "\n"


if __name__ == '__main__':
    reactor.listenTCP(8081, server.Site(HelloResource()))
    reactor.run()
