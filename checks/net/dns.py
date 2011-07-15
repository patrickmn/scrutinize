#!/usr/bin/env python
import os
import socket
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet import error
from twisted.names import error
from twisted.names.common import extractRecord
# from twisted.names.client import getResolver
from common import getResolver # XXX: See common.py
from twisted.names.client import dns
from twisted.names.client import Resolver
from twisted.names.client import DNSClientFactory
from twisted.python.failure import Failure

import common
from check import DomainCheck
from check import HostCheck
from err import *

class ZoneTransferRefusedResolver(Resolver):

    def connectionLost(self, reason):
        pass

class ZoneTransferRefusedAXFRController(object):

    timeoutCall = None

    def __init__(self, name, deferred):
        self.name = name
        self.deferred = deferred

    def connectionMade(self, protocol):
        message = dns.Message(protocol.pickID(), recDes=0)
        message.queries = [dns.Query(self.name, dns.AXFR, dns.IN)]
        protocol.writeMessage(message)

    def connectionLost(self, protocol):
	pass

    def messageReceived(self, message, protocol):
        if self.timeoutCall is not None:
            self.timeoutCall.cancel()
            self.timeoutCall = None
        if self.deferred is not None:
            self.deferred.callback(message)
            self.deferred = None

class ZoneTransferRefused(DomainCheck):
    """Nameservers refuse zone transfer (AXFR)"""

    def __init__(self, *args, **kwargs):
        super(ZoneTransferRefused, self).__init__(*args, **kwargs)
        self.resolver = getResolver()

    def extractAllAddressRecords(self, name, answers, effort):
        # Derivation of twisted.names.client.extractRecord/_cbRecords that
        # returns all possible addresses.
        addresses = []
        if not effort:
            return None
        for x in answers:
            if x.name == name:
                if hasattr(socket, 'inet_ntop') and x.type in (dns.A6, dns.AAAA):
                    addresses.append(socket.inet_ntop(socket.AF_INET6, x.payload.address))
                elif x.type == dns.A:
                    addresses.append(socket.inet_ntop(socket.AF_INET, x.payload.address))
                elif x.type == dns.CNAME:
                    result = extractRecord(self.resolver, x.payload.name, answers, effort - 1)
                    if result:
                        addresses.append(result)
        if not addresses:
            for x in answers:
                if x.type == dns.NS:
                    r = ZoneTransferRefusedResolver(servers=[(str(x.payload.name), dns.PORT)])
                    d = (r.lookupAddress(str(name))
                         .addCallback(lambda (ans, auth, add): extractRecord(r, name, ans + auth + add, effort - 1)))
                    addresses.append(d)
        return list(set(addresses))

    def getAllPossibleHosts(self, name):
        d = (self.resolver.lookupAllRecords(name)
             .addCallback(lambda (ans, auth, add): self.extractAllAddressRecords(dns.Name(name), ans + auth + add, effort=20)))
        return d

    def doAXFRRequest(self, name, host, port = dns.PORT, timeout = 10):
        d = defer.Deferred()
        controller = ZoneTransferRefusedAXFRController(name, d)
        factory = DNSClientFactory(controller, timeout)
        factory.noisy = False

        connector = reactor.connectTCP(host, port, factory)
        controller.timeoutCall = reactor.callLater(timeout or 10, self._timeoutZone, d, controller, connector, timeout or 10)
        return d.addCallback(self._cbDoAXFRRequest, connector)

    def _cbDoAXFRRequest(self, result, connector):
        connector.disconnect()
        return result

    def _timeoutZone(self, d, controller, connector, seconds):
        connector.disconnect()
        controller.timeoutCall = None
        controller.deferred = None
        d.errback(error.TimeoutError("Timeout after %ds" % (seconds,)))

    def tryZoneTransferTCP(self, nameserver):
        d = (self.doAXFRRequest(self.target, nameserver)
             .addCallback(lambda res: self.addSubresult('(TCP) NS: {0}'.format(nameserver), not res.answers, 'AXFR allowed' if res.answers else ''))
             .addErrback(lambda res: self.addSubresult('(TCP) NS: {0}'.format(nameserver), CHECK_RESULT_UNCERTAIN, failure=res)))
        return d

    def tryZoneTransferUDP(self, nameserver):
        r = ZoneTransferRefusedResolver(servers=[(nameserver, dns.PORT),])
        d = (r.queryUDP([dns.Query(self.target, dns.AXFR, dns.IN),])
             .addCallback(lambda res: self.addSubresult('(UDP) NS: {0}'.format(nameserver), not res.answers, 'AXFR allowed' if res.answers else ''))
             .addErrback(lambda res: self.addSubresult('(UDP) NS: {0}'.format(nameserver), CHECK_RESULT_UNCERTAIN, failure=res)))
        return d

    def runZoneTransfers(self, nameservers):
        sem = common.getSemaphore()
        deferreds = []
        for ns in nameservers:
            deferreds.append(sem.run(self.tryZoneTransferTCP, ns))
            deferreds.append(sem.run(self.tryZoneTransferUDP, ns))
        dl = defer.DeferredList(deferreds)
        return dl

    def _getHosts(self, (ans, auth, add)):
        targets = [str(x.payload.name) for x in ans]
        dl = (common.semMap(self.getAllPossibleHosts, targets)
              .addCallback(self._cbGetHosts))
        dl.consumeErrors = True
        return dl

    def _cbGetHosts(self, dl):
        # getHosts dl gives list of (status, result) where result is
        # list of lists of IP addresses... e.g.:
        # [(True, ['202.148.152.225', '8.8.8.8]),
        #  (True, ['129.178.88.72']),
        #  (True, ['203.27.227.61', '2.2.2.2']),
        #  (True, ['129.178.88.65'])
        # ]
        results = []
        valid = [x[1] for x in dl if x[0]]
        for addressSet in valid:
            for address in addressSet:
                results.append(address)
        return results

    def run(self):
        self.setResult(CHECK_RESULT_SUB)
        d = (self.resolver.lookupNameservers(self.target)
             .addCallback(self._getHosts)
             .addCallback(self.runZoneTransfers))
        return d

class MXRecordsExist(DomainCheck):
    """MX records exist"""

    def run(self):
        r = getResolver()
        d = (r.lookupMailExchange(self.target)
             .addCallback(lambda (ans, auth, add): self.setResult(bool(ans))))
        return d

class ValidRDNS(HostCheck):
    """RDNS points back to the host"""

    def __init__(self, *args, **kwargs):
        super(ValidRDNS, self).__init__(*args, **kwargs)
        self.resolver = getResolver()

    def errorHandler(self, failure):
        self.setResult(CHECK_NOT_APPLICABLE, extra='No RDNS PTR')
        return failure

    def run(self):
        if self.target not in ('127.0.0.1', '::1'):
            d = (common.reverseHostLookup(self.target)
                 .addErrback(self.errorHandler)
                 .addCallback(self.resolver.getHostByName)
                 .addCallback(lambda newhost: self.setResult(newhost == self.target)))
        else:
            self.setResult(CHECK_NOT_APPLICABLE)
            d = defer.Deferred()
            reactor.callLater(0, d.callback, "herp derp")
        return d
