import httplib
import logging
import string

try:
    import simplejson as json 
except ImportError:
    import json


srv_hostport = None
srv_conn = None

def init(options=None):
    global srv_conn, srv_hostport
    if options:
        srv_hostport = options.server
    srv_conn = httplib.HTTPConnection(srv_hostport)

def soap_request_handler(conn, endpoint, headers, payload, body_child):
    """Sample request handler which simply posts soap call data to our statistics server"""
    # the first body child is the method for SOAP-RPC
    namespace_uri, tag = string.split(body_child.tag[1:], "}", 1)
    args = {}
    # children of the method tag are the method's arguments
    for arg in body_child:
        args[arg.tag] = arg.text
    d = [endpoint, tag, args]
    try:
        srv_conn.request("POST", "/deque", json.dumps(d))
        response = srv_conn.getresponse()
        response.read()
    except Exception, e:
        logging.exception('Error posting soap data to server')
        # reinit connection in case of error
        init()
