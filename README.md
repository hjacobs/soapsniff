SOAP Sniffer
============

Captures TCP packets and handles HTTP and SOAP requests
to track call/request statistics and trigger custom handlers.

Requirements
------------

* python 2.6+
* pcapy
* impacket

Using Debian/Ubuntu simply do:

    sudo apt-get install python-pcapy python-impacket

The sniffer also runs with Python 2.5 if you install the simplejson package.


Running
-------

Start server (default port 8080) and packet sniffer on same host:

    ./server.py && sudo ./soapsniff.py -v -s localhost:8080


