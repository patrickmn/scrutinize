from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import ClientFactory

import common
from check import HostCheck
from err import *

generalPortDescriptions = {
    20: 'FTP (Data)',
    21: 'FTP (Control)',
    22: 'SSH',
    23: 'Telnet',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    150: 'NetBIOS',
    156: 'SQL Server',
    161: 'SNMP',
    179: 'Border Gateway Protocol',
    194: 'IRC',
    389: 'LDAP',
    443: 'HTTPS',
    546: 'DHCP (Client)',
    547: 'DHCP (Server)',
    569: 'MSN',
    587: 'Submission',
    993: 'IMAPS',
    1080: 'SOCKS',
    8080: 'HTTP',
}

malwarePorts = {
    1080: 'MyDoom.B, MyDoom.F, MyDoom.G, MyDoom.H',
    2283: 'Dumaru.Y',
    2535: 'Beagle.W, Beagle.X, other variants',
    2745: 'Beagle.C through Beagle.K',
    3127: 'MyDoom.A',
    3128: 'MyDoom.B',
    3410: 'Backdoor.OptixPro.13 variants',
    5554: 'Sasser.C through Sasser.F',
    8866: 'Beagle.B',
    9898: 'Dabber.A, Dabber.B',
    10000: 'Dumaru.Y',
    10080: 'MyDoom.B',
    12345: 'NetBus',
    17300: 'Kuang2',
    27374: 'SubSeven',
    65506: 'PhatBot, Agobot, Gaobot',
}

commonPorts = [
    20, 21, 22, 23, 53, 80, 110, 143, 150, 156, 161, 179,
    194, 389, 443, 546, 547, 569, 587, 993, 1080, 8080
]

class PortScanProtocol(Protocol):

    def connectionMade(self):
        self.factory.deferred.callback("success")
        self.transport.loseConnection()

class PortScanFactory(ClientFactory):

    protocol = PortScanProtocol

    def __init__(self):
        self.deferred = defer.Deferred()

    def clientConnectionFailed(self, unused, reason):
        self.deferred.errback(reason)
        self.deferred = None

    def clientConnectionLost(self, connector, reason):
        pass

class PortScan(HostCheck):
    """Open TCP ports"""

    def __init__(self, *args, **kwargs):
        super(PortScan, self).__init__(*args, **kwargs)
        self.ports = []
        self.timeout = 10
        self.descriptions = generalPortDescriptions

    def prepare(self):
        deferreds = []
        sem = common.getSemaphore()
        if isinstance(self.ports, dict):
            self.descriptions = self.ports
            self.ports = self.ports.keys()
        for port in self.ports:
            d = sem.run(self.doFactory, port)
            deferreds.append(d)
        dl = defer.DeferredList(deferreds, consumeErrors=False)
        return dl

    def run(self):
        self.setResult(CHECK_RESULT_SUB)
        d = self.prepare()
        return d

    def doFactory(self, port):
        factory = PortScanFactory()
        reactor.connectTCP(self.target, port, factory, timeout=self.timeout)
        d = factory.deferred
        d.addCallback(self.gotConnection, port)
        d.addErrback(self.gotFailure, port)
        return d

    def gotConnection(self, unused, port):
        extra = self.descriptions.get(port)
        self.addSubresult(str(port), True, extra)

    def gotFailure(self, failure, port):
        pass

class CommonPortScan(PortScan):
    """Open TCP ports (common)"""

    def __init__(self, *args, **kwargs):
        super(CommonPortScan, self).__init__(*args, **kwargs)
        self.ports = commonPorts

class MalwarePortScan(PortScan):
    """Open TCP ports often used by malware"""

    def __init__(self, *args, **kwargs):
        super(MalwarePortScan, self).__init__(*args, **kwargs)
        self.ports = malwarePorts
