#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Simple SOAP/HTTP packet sniffer
written by henning@jacobs1.de
"""

import os
import signal
import sys
import string
import StringIO
import time
import logging
from optparse import OptionParser
from threading import Thread

import pcapy
from pcapy import open_live
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import httplib
import collections
import re
import xml.etree.ElementTree
from xml.parsers.expat import ExpatError
from collections import Counter

import json

ENVELOPE_END = re.compile('</[a-zA-Z-]+:Envelope>')
ENVELOPE_END_ANCHORED = re.compile('</[a-zA-Z-]+:Envelope>\s*$')
NS_SOAP_ENV = '{http://schemas.xmlsoap.org/soap/envelope/}'
IPV4_ADDRESS = re.compile('^\d+\.\d+\.\d+\.\d+$')


class Connection(object):

    """A TCP connection (identified by pair of sockets)"""

    def __init__(self, socket_pair):
        self.src = socket_pair[0]
        self.dst = socket_pair[1]
        self.deque = collections.deque()
        self.is_soap = False
        self.last_packet_received = 0

    def __str__(self):
        return 'Connection from %s:%s to %s:%s' % (self.src[0], self.src[1], self.dst[0], self.dst[1])

    def append_packet(self, tcp_seq, data):
        self.last_packet_received = time.time()
        if not self.deque or tcp_seq > self.deque[-1][0]:
            self.deque.append((tcp_seq, data))
        else:
            last = self.deque.pop()
            self.deque.append((tcp_seq, data))
            self.deque.append(last)

    def get_stream(self):
        return ''.join([dat for (s, dat) in self.deque])


class ConnectionManager(object):

    """Container for list of active connections"""

    def __init__(self):
        self.connections = {}

    def __len__(self):
        return len(self.connections)

    def __getitem__(self, socket_pair):
        return self.connections.setdefault(socket_pair, Connection(socket_pair))

    def __delitem__(self, socket_pair):
        del self.connections[socket_pair]

    def remove_idle(self):
        """remove all connections which did not receive data packets in the last minute"""

        deadline = time.time() - 60.0
        for key, conn in self.connections.items():
            if conn.last_packet_received < deadline:
                del self.connections[key]


class ClockThread(Thread):

    """simple timer thread which calls a given function periodically"""

    def __init__(self, interval, callback):
        self.interval = interval
        self.callback = callback
        Thread.__init__(self)
        self.daemon = True

    def run(self):
        while True:
            time.sleep(self.interval)
            self.callback()


class DecoderThread(Thread):

    """main thread which handles TCP packets and HTTP/SOAP"""

    def __init__(self, pcapObj, server_ports, ws_path, soap_request_handler, server):
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception('Datalink type not supported: %s' % (datalink, ))

        self.pcap = pcapObj
        self.server_ports = set(server_ports)
        self.ws_path = ws_path
        self.server = server
        self.soap_request_handler = soap_request_handler
        self.valid_http_methods = set(['GET', 'POST'])
        self._shortest_method_name = min([len(x) for x in self.valid_http_methods])
        self._longest_method_name = max([len(x) for x in self.valid_http_methods])
        Thread.__init__(self)
        self.packet_counter = 0
        self.connections = ConnectionManager()
        self.http_request_counter = Counter()
        self.soap_call_counter = Counter()
        self.server_conn = None
        self._needs_server_update = False
        self._last_server_update = 0

    def _init_server_conn(self):
        if self.server:
            self.server_conn = httplib.HTTPConnection(self.server)

    def run(self):
        self._init_server_conn()
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        self.pcap.loop(0, self.handle_packet)

    def _read_chunked(self, fp):
        value = []
        chunk_left = None
        while True:
            if chunk_left is None:
                line = fp.readline()
                i = line.find(';')
                if i >= 0:
                    line = line[:i]  # strip chunk-extensions
                try:
                    chunk_left = int(line, 16)
                except ValueError:
                    raise Exception(''.join(value))
                if chunk_left == 0:
                    break
            value.append(fp.read(chunk_left))

            # we read the whole chunk, get another
            fp.read(2)  # toss the CRLF at the end of the chunk
            chunk_left = None

        # read and discard trailer up to the CRLF terminator
        # ## note: we shouldn't have any trailers!
        while True:
            line = fp.readline()
            if not line:
                # a vanishingly small number of sites EOF without
                # sending the trailer
                break
            if line == '\r\n':
                break

        return ''.join(value)

    def handle_http_request(self, conn, method, data):
        try:
            request_path = data[len(method) + 1:data.index(' ', len(method) + 2)]
        except ValueError:
            logging.warning('Invalid HTTP request line: %s', data[:100])
            return
        logging.debug('Received %s %s', method, request_path)
        self.http_request_counter.inc((
            conn.src[0],
            conn.dst[0],
            conn.dst[1],
            method,
            request_path,
        ))
        self._needs_server_update = True

        # SOAP requests must be POST
        # see http://www.w3.org/TR/2007/REC-soap12-part0-20070427/#L26866
        if method == 'POST':
            if request_path.startswith(self.ws_path):
                conn.is_soap = True

    def handle_soap_request(self, conn):
        logging.debug('handle_soap_request')
        chunk = ''
        first = True
        while conn.deque:
            seq, packet = conn.deque.popleft()
            if not first and packet.startswith('POST /'):
                conn.deque.append((seq, packet))
                break
            chunk += packet
            first = False
        # if not conn.deque:
        #    del self.connections[conn]
        fd = StringIO.StringIO(chunk)
        encoding_chunked = False
        first = True
        firstline = ''
        headers = []
        x_forwarded_for = '-'
        while True:
            line = fd.readline().strip()
            if first:
                firstline = line
                first = False
            else:
                headers.append(line)
                name, sep, val = line.partition(':')
                if name.lower() == 'x-forwarded-for' and IPV4_ADDRESS.match(val.strip()):
                    x_forwarded_for = val.strip()
            if not line:
                break
            if 'chunked' in line:
                encoding_chunked = True
        if encoding_chunked:
            try:
                payload = self._read_chunked(fd)
            except:
                payload = ''
        else:
            payload = fd.read()
        if firstline.startswith('POST /') and ENVELOPE_END_ANCHORED.search(payload):
            try:
                envelope = xml.etree.ElementTree.fromstring(payload)
            except ExpatError, e:
                logging.warning('Could not parse SOAP payload for %s: %s', firstline, e)
                return
            body = envelope.find(NS_SOAP_ENV + 'Body')
            body_child = None
            for child in body:
                namespace_uri, method = string.split(child.tag[1:], '}', 1)
                body_child = child
            endpoint = firstline.split(' ')[1]
            self.soap_call_counter.inc((
                x_forwarded_for,
                conn.src[0],
                conn.dst[0],
                conn.dst[1],
                endpoint,
                method,
            ))
            self._needs_server_update = True
            self.soap_request_handler(conn, firstline.split(' ')[1], headers, payload, body_child)

    def update_server(self):
        logging.debug('Updating server')
        post_data = {'soap': {}, 'http': {}}
        for key, val in self.http_request_counter.items():
            post_data['http'][' '.join(map(str, key))] = val
        for key, val in self.soap_call_counter.items():
            post_data['soap'][' '.join(map(str, key))] = val
        try:
            self.server_conn.request('POST', '/counter', json.dumps(post_data))
            response = self.server_conn.getresponse()
            response.read()
        except:
            logging.exception('Error while posting to server')
            self._init_server_conn()

        self._last_server_update = time.time()
        self._needs_server_update = False

    def clock_tick(self):
        if self.server_conn and self._needs_server_update:
            self.update_server()

    def handle_packet(self, hdr, data):
        """pcap packet handler"""

        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        a = self.decoder.decode(data)
        ip = a.child()
        tcp = ip.child()

        if tcp.get_th_dport() not in self.server_ports:
            # currently we ignore all response packets!
            return

        try:
            self._handle_tcp_packet(ip, tcp)
        except:
            logging.exception('Error while processing TCP packet: %s', tcp)

    def _handle_tcp_packet(self, ip, tcp):
        """handle a single TCP/IP packet"""

        self.packet_counter += 1
        if self.packet_counter % 10 == 0:
            logging.debug('Received %d packets so far', self.packet_counter)

        src = ip.get_ip_src(), tcp.get_th_sport()
        dst = ip.get_ip_dst(), tcp.get_th_dport()
        socket_pair = src, dst

        if self.packet_counter % 10 == 0:
            self.connections.remove_idle()

        conn = self.connections[socket_pair]

        logging.debug('Connections: %d', len(self.connections))

        data = tcp.get_data_as_string()
        conn.append_packet(tcp.get_th_seq(), data)

        try:
            http_method = data[:data.index(' ', self._shortest_method_name, self._longest_method_name + 1)]
        except ValueError:
            # HTTP method could not be parsed => probably a data packet
            http_method = None

        if http_method in self.valid_http_methods:
            self.handle_http_request(conn, http_method, data)

        if conn.is_soap and ENVELOPE_END.search(conn.get_stream(), 20):
            self.handle_soap_request(conn)


class Watcher:

    """this class solves two problems with multithreaded
    programs in Python, (1) a signal might be delivered
    to any thread (which is just a malfeature) and (2) if
    the thread that gets the signal is waiting, the signal
    is ignored (which is a bug).

    The watcher is a concurrent process (not thread) that
    waits for a signal and the process that contains the
    threads.  See Appendix A of The Little Book of Semaphores.
    http://greenteapress.com/semaphores/

    I have only tested this on Linux.  I would expect it to
    work on the Macintosh and not work on Windows.
    """

    def __init__(self):
        """ Creates a child thread, which returns.  The parent
            thread waits for a KeyboardInterrupt and then kills
            the child thread.
        """

        self.child = os.fork()
        if self.child == 0:
            return
        else:
            self.watch()

    def watch(self):
        try:
            os.wait()
        except KeyboardInterrupt:
            # I put the capital B in KeyBoardInterrupt so I can
            # tell when the Watcher gets the SIGINT
            print 'KeyBoardInterrupt'
            self.kill()
        sys.exit()

    def kill(self):
        try:
            os.kill(self.child, signal.SIGKILL)
        except OSError:
            pass


def default_soap_request_handler(conn, endpoint, headers, payload, body_child):
    namespace_uri, tag = string.split(body_child.tag[1:], '}', 1)
    logging.debug('SOAP %s %s (%s)', endpoint, tag, conn)


def main(dev, server_ports, filter, ws_path, soap_request_handler, server):
    """main function which starts up the decoder thread"""

    Watcher()

    # Open interface for catpuring.
    p = open_live(dev, 64 * 1024, 0, 100)

    # Set the BPF filter. See tcpdump(3).
    p.setfilter(filter)

    logging.info('Listening on %s: net=%s, mask=%s, linktype=%d' % (dev, p.getnet(), p.getmask(), p.datalink()))

    # Start sniffing thread and finish main thread.
    t = DecoderThread(p, server_ports, ws_path, soap_request_handler, server)
    clock = ClockThread(0.5, t.clock_tick)
    t.start()
    clock.start()


if __name__ == '__main__':

    parser = OptionParser(description=__doc__)
    parser.add_option('-d', '--dev', dest='dev', default='eth0', help='device to listen on (default: eth0)',
                      metavar='DEV')
    parser.add_option('-p', '--ports', dest='ports', default='80,8080', help='ports to listen on (default: 80,8080)',
                      metavar='PORTS')
    parser.add_option('-w', '--ws-path', dest='ws_path', metavar='PREFIX', default='/',
                      help='web service path prefix (e.g. /ws)')
    parser.add_option('-c', '--soap-request-handler', dest='soap_request_handler', metavar='CALLABLE',
                      help='soap request handler callback')
    parser.add_option('-s', '--server', dest='server', metavar='HOST_PORT', help='server host and port')
    parser.add_option('-v', '--verbose', dest='verbose', action='store_true', help='output debug information')

    options, args = parser.parse_args()

    log_level = logging.INFO
    if options.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    ports = []
    ports_filter = ''

    if options.ports:
        parts = options.ports.split(',')
        for part in parts:
            range_start_end = part.split('-')
            if len(range_start_end) == 2:
                ports += range(int(range_start_end[0]), int(range_start_end[1]) + 1)
            else:
                ports.append(int(range_start_end[0]))
        ports_filter = ' or '.join(['(port %s)' % (p, ) for p in ports])
        ports_filter = ' and (' + ports_filter + ')'

    # we only capture packets which contain data:
    # ip[2:2]        : 16-bit IP total length
    # (ip[0]&0xf)<<2 : 4-bit IP header length
    # (tcp[12]&0xf0) : TCP header length
    filter = 'tcp ' + ports_filter + ' and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
    logging.debug('BPF filter: %s', filter)

    if options.soap_request_handler:
        parts = options.soap_request_handler.split('.')
        module = __import__('.'.join(parts[:-1]))
        if callable(getattr(module, 'init', None)):
            module.init(options)
        soap_request_handler = getattr(module, parts[-1])
    else:
        soap_request_handler = default_soap_request_handler

    main(options.dev, ports, filter, options.ws_path, soap_request_handler, options.server)

