#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Statistics server for SOAP/HTTP sniffer.
Holds request counts.
"""

import time
import BaseHTTPServer
import SocketServer
import collections
import json
import logging
from optparse import OptionParser


class DerivativeCounter(object):

    """calculate derivate (increments/sec) of dictionary counter values"""

    def __init__(self, maxlen=60):
        self.maxlen = maxlen
        self.update_interval = 2
        self.timestamps = collections.deque([], maxlen)
        self.values = collections.deque([], maxlen)

    def update(self, _values):
        now = time.time()
        if not self.timestamps or now - self.timestamps[-1] > self.update_interval:
            # push new values into deque
            cur = self.current().copy()
            cur.update(_values)
            self.timestamps.append(now)
            self.values.append(cur)
        else:
            # just update our most recent counter values
            self.current().update(_values)

    def current(self):
        """current counter values"""

        if not self.values:
            return {}
        return self.values[-1]

    def average_per_sec(self, timespan=60):
        """return dictionary with increments/sec for each key"""

        if not self.values:
            return {}
        now = self.timestamps[-1]
        if time.time() - now > 2 * self.update_interval:
            # last update was too long ago
            # => we assume that counters did not change
            # and we calculate average based on current time
            now = time.time() - self.update_interval
        startidx = 0
        dt = now - self.timestamps[startidx]
        while dt > timespan and startidx < len(self.timestamps) - 2:
            startidx += 1
            dt = now - self.timestamps[startidx]
        if not dt:
            # no time difference => we can't compute any derivate
            return {}
        dv = self.values[-1].copy()
        startvalues = self.values[startidx]
        for key, val in dv.items():
            dv[key] = (val - startvalues.get(key, 0)) / dt
        return dv


class SoapCallGrouper(object):

    @classmethod
    def group(cls, data, by):
        if by == 'method':
            keyfunc = lambda k: ' '.join(k.split(' ')[4:6])
        elif by == 'connection':
            keyfunc = lambda k: ' '.join(k.split(' ')[:4])
        result = collections.defaultdict(int)
        for key, val in data.items():
            result[keyfunc(key)] += val
        return result


class SimpleHttpRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        separators = ',', ':'
        if 'pretty' in self.path:
            separators = ',\n', ': '
        if self.path.startswith('/deque'):
            data = list(self.server.get_data())
        elif self.path.startswith('/derivate'):
            if 'soap' in self.path:
                data = self.server.soap_call_counter.average_per_sec()
                if 'method' in self.path:
                    data = SoapCallGrouper.group(data, 'method')
                elif 'connection' in self.path:
                    data = SoapCallGrouper.group(data, 'connection')
            elif 'http' in self.path:
                data = self.server.http_request_counter.average_per_sec()
            else:
                data = {'http': self.server.http_request_counter.average_per_sec(),
                        'soap': self.server.soap_call_counter.average_per_sec()}
        else:
            data = {'http': self.server.http_request_counter.current(), 'soap': self.server.soap_call_counter.current()}
        json.dump(data, self.wfile, separators=separators)

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
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write('OK')


class MyWebServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):

    def init(self):
        self.deque = collections.deque([], 500)
        self.http_request_counter = DerivativeCounter()
        self.soap_call_counter = DerivativeCounter()

    def append_data(self, data):
        self.deque.append((time.time(), data))

    def get_data(self):
        return self.deque

    def update_counters(self, data):
        self.http_request_counter.update(data['http'])
        self.soap_call_counter.update(data['soap'])


if __name__ == '__main__':
    parser = OptionParser(description=__doc__)
    parser.add_option('-p', '--port', dest='port', default=8080, help='port to listen on (default: 8080)',
                      metavar='PORT')
    parser.add_option('-v', '--verbose', dest='verbose', action='store_true', help='output debug information')

    options, args = parser.parse_args()

    log_level = logging.INFO
    if options.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    server_address = '', int(options.port)
    httpd = MyWebServer(server_address, SimpleHttpRequestHandler)
    httpd.init()
    sa = httpd.socket.getsockname()
    logging.info('Serving HTTP on {0} port {1}...'.format(sa[0], sa[1]))
    httpd.serve_forever()

