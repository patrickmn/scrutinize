#!/usr/bin/env python
try:
    from twisted.internet import epollreactor
    epollreactor.install()
except:
    pass

import sys
from twisted.internet import defer
from twisted.python.failure import Failure

import common
from cli import BaseCLI
from cli import ArgParser
from scanner import HostScanner
from err import ScrutinizeException
from color import colorize

import checks.net.dns
import checks.net.ports
hostChecks = (
    checks.net.dns.ValidRDNS,
    checks.net.ports.CommonPortScan,
    checks.net.ports.MalwarePortScan,
)

class AddressValidityError(ScrutinizeException):
    pass

class HostScanCLI(BaseCLI):

    def __init__(self):
        super(HostScanCLI, self).__init__()
        self.scanner = HostScanner
        self.checks = hostChecks

        p = ArgParser(
            description = 'Scrutinize Host Scanner',
            epilog = 'Use @ to read arguments from file, e.g.: {0} @hostlist.txt'.format(sys.argv[0]),
            fromfile_prefix_chars='@',
        )
        p.add_argument('-c', '--checks',
                       nargs = '+',
                       choices = [x.__module__.replace('checks.', '') + '.' + x.__name__ for x in hostChecks],
                       metavar = ('net.dns.TestA', 'net.http.TestB'),
                       help = 'specific checks to run')
        p.add_argument('-t', '--throttle',
                       type = int,
                       default = 10,
                       metavar = '10',
                       help = 'actions to perform concurrently')
        p.add_argument('-v', '--verbose',
                       action = 'store_true',
                       help = 'display additional debug information')
        p.add_argument('-w', '--warnings-only',
                       action = 'store_true',
                       help = 'only show results for tests that return warnings')
        p.add_argument('--no-color',
                       action = 'store_false',
                       dest = 'color',
                       help = 'disable output text coloring')
        p.add_argument('--class-names',
                       action = 'store_true',
                       dest = 'useCheckClassNames',
                       help = 'show names of checks rather than descriptions')
        p.add_argument('addresses',
                       nargs = '+',
                       metavar = 'server1.example.com',
                       help = 'target IP address(es)/hostname(s)')
        self.parser = p

    def modifyArgs(self, args):
        if args.checks:
            self.checks = [eval('checks.' + x) for x in args.checks]
        resolved = self.resolveAddresses(args)
        # resolveAddresses might have removed enough addresses to make the list empty.
        if not args.addresses:
            raise AddressValidityError("None of the hostnames listed were valid.")
        return resolved

    def resolveAddresses(self, args):
        # r = common.getResolver()
        self.resolveMap = {}
        multipleUnresolved = False
        for address in args.addresses:
            if not common.isIPAddress(address):
                if common.isHostname(address):
                    # TODO: Use twisted.names.client's getHostByName without removing
                    #       the hostfile resolver from the resolverchain.
                    #       (Right now, the standard behavior of using the resolverchain
                    #       hostsresolver -> cacheresolver -> resolver triggers an error when
                    #       you try to look up a domain that matches an IP address defined
                    #       in the hosts file--"noneType has no function stopListening" in
                    #       the passthrough.)

                    # d = r.getHostByName(address)
                    # self.resolveMap[address] = d

                    # Blocking, but it's ok. We'd be waiting anyway.
                    import socket
                    if not multipleUnresolved:
                        print(colorize(" @Y*@x {0:51} @B[---]@x".format("Resolving hostnames...")))
                        multipleUnresolved = True
                    sys.stdout.write(colorize("   @y-@x {0:28} ".format(address)))
                    sys.stdout.flush()
                    try:
                        new = socket.getaddrinfo(address, 80, 0, 0, socket.SOL_TCP)[0][4][0]
                    except (socket.error, socket.herror, socket.gaierror, socket.timeout):
                        self.resolveMap[address] = Failure()
                        print(colorize("{0:<20} @B[@R!!!@B]@x".format("Not found")))
                        continue
                    print(colorize("{0:<20} @B[ @G- @B]@x".format(new)))
                    self.resolveMap[address] = new
                else:
                    raise TypeError("Please specify only IP addresses or hostnames in --address; {0} is invalid.".format(address))
        # deferreds = self.resolveMap.values()
        # dl = (defer.DeferredList(deferreds)
        #       .addCallback(self._cbResolveAddresses, args))
        # return dl
        return self._cbResolveAddresses(None, args)

    def _cbResolveAddresses(self, res, args):
        newAddresses = []
        for address in args.addresses:
            new = self.resolveMap.get(address)
            if new:
                self.addressTitles[new] = "{0} ({1})".format(address, new)
                if not isinstance(new, Failure):
                    newAddresses.append(new)
            else:
                newAddresses.append(address)
        args.addresses = newAddresses
        return args

def main():
    return HostScanCLI().run()

if __name__ == '__main__':
    main()
