#!/usr/bin/env python
"""
Statistics server for SOAP/HTTP sniffer.
Holds request counts.
"""

import os
import time
import BaseHTTPServer
import SocketServer
import threading
import sys
import collections
import json
import logging
from optparse import OptionParser

class SimpleHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type",'text/plain')
        self.end_headers()
        separators = (',', ':')
        if 'pretty' in self.path:
            separators = (',\n', ': ')
        if self.path.startswith('/deque'):
            json.dump(list(self.server.get_data()), self.wfile, separators=separators)
        else:
            json.dump({'http': self.server.http_request_counter, 'soap': self.server.soap_call_counter}, self.wfile, separators=separators)

    def do_POST(self):
        raw_data = self.rfile.read(int(self.headers['Content-Length']))
        try:
            data = json.loads(raw_data)
        except:
            data = raw_data
        if self.path.startswith('/deque'):
            self.server.append_data(data)
        else:
            self.server.update_counters(data)
        self.send_response(200)
        self.send_header("Content-type",'text/plain')
        self.send_header("Content-Length",'2')
        self.end_headers()
        self.wfile.write("OK")

class myWebServer(SocketServer.ThreadingMixIn,BaseHTTPServer.HTTPServer):
    def init(self):
        self.deque = collections.deque([], 500)
        self.http_request_counter = {}
        self.soap_call_counter = {}
    def append_data(self, data):
        self.deque.append((time.time(), data))
    def get_data(self):
        return self.deque
    def update_counters(self, data):
        self.http_request_counter.update(data['http'])
        self.soap_call_counter.update(data['soap'])
            

if __name__ == '__main__':
    parser = OptionParser(description=__doc__)
    parser.add_option("-p", "--port", dest="port",
        default=8080,
        help="port to listen on (default: 8080)", metavar="PORT")
    parser.add_option("-v", "--verbose", dest="verbose",
        action='store_true',
        help="output debug information" )

    options, args = parser.parse_args()

    log_level = logging.INFO
    if options.verbose: log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    server_address = ('',int(options.port))
    httpd=myWebServer(server_address,SimpleHTTPRequestHandler)
    httpd.init()
    sa=httpd.socket.getsockname()
    logging.info("Serving HTTP on {0} port {1}...".format(sa[0], sa[1]))
    httpd.serve_forever()

