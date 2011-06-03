import re
from twisted.internet import defer
from twisted.names.client import Resolver

import config
import log

def show(x):
    print(x)
    return x

def chunks(things, chunkSize):
    for i in xrange(0, len(things), chunkSize):
        yield things[i:i+chunkSize]

hostnameRe = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
def isHostname(host):
    if len(host) > 255:
        return False
    if host[-1:] == ".":
        host = host[:-1] # strip exactly one dot from the right, if present
    return all(hostnameRe.match(x) for x in host.split("."))

def isIPAddress(addr):
    dottedParts = addr.split('.')
    if len(dottedParts) == 4:
        for octet in dottedParts:
            try:
                value = int(octet)
            except ValueError:
                return False
            else:
                if value < 0 or value > 255:
                    return False
        return True
    return False

theSemaphore = None
def getSemaphore():
    global theSemaphore
    if theSemaphore is None:
        theSemaphore = defer.DeferredSemaphore(config.throttle)
    return theSemaphore

def semMap(function, things, *args, **kwargs):
    assert callable(function)
    sem = getSemaphore()
    deferreds = []
    for x in things:
        d = sem.run(function, x, *args, **kwargs)
        deferreds.append(d)
    dl = defer.DeferredList(deferreds)
    return dl

def reverseHostLookup(ip):
    # TODO: Reverse DNS lookups for IPv6 addresses use the special domain ip6.arpa.
    #       An IPv6 address appears as a name in this domain as a sequence of nibbles
    #       in reverse order, represented as hexadecimal digits as subdomains. For example,
    #       the pointer domain name corresponding to the IPv6 address 2001:db8::567:89ab is
    #       b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
    r = getResolver()
    ptr = '.'.join(ip.split('.')[::-1]) + '.in-addr.arpa'
    d = (r.lookupPointer(ptr)
         .addCallback(lambda (ans, auth, add): str(ans[0].payload.name)))
    return d

### XXX: Begin Resolver hack
# Copy-pasta until twisted.names.client's Resolver has connectionLost defined
from twisted.python.runtime import platform

class HardcoreResolver(Resolver):

    def connectionLost(self, reason):
        pass

def createResolver(servers=None, resolvconf=None, hosts=None):
    from twisted.names import resolve, cache, root, hosts as hostsModule
    if platform.getType() == 'posix':
        if resolvconf is None:
            resolvconf = '/etc/resolv.conf'
        if hosts is None:
            hosts = '/etc/hosts'
        theResolver = HardcoreResolver(resolvconf, servers)
        hostResolver = hostsModule.Resolver(hosts)
    else:
        if hosts is None:
            hosts = r'c:\windows\hosts'
        from twisted.internet import reactor
        bootstrap = _ThreadedResolverImpl(reactor)
        hostResolver = hostsModule.Resolver(hosts)
        theResolver = root.bootstrap(bootstrap)

    L = [hostResolver, cache.CacheResolver(), theResolver]
    return resolve.ResolverChain(L)

theResolver = None
def getResolver():
    global theResolver
    if theResolver is None:
        try:
            theResolver = createResolver()
        except ValueError:
            theResolver = createResolver(servers=[('127.0.0.1', 53)])
    return theResolver
### End Resolver hack
