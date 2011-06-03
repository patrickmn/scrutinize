#!/usr/bin/env python
try:
    from twisted.internet import epollreactor
    epollreactor.install()
except:
    pass

import sys
from twisted.internet import defer

import common
from cli import BaseCLI
from cli import ArgParser
from scanner import DomainScanner

import checks.net.dns
import checks.net.httpd
domainChecks = (
    checks.net.dns.ZoneTransferRefused,
    checks.net.dns.MXRecordsExist,
    checks.net.httpd.UnexposedFiles,
)

class DomainScanCLI(BaseCLI):

    def __init__(self):
        super(DomainScanCLI, self).__init__()
        self.scanner = DomainScanner
        self.checks = domainChecks

        p = ArgParser(
            description = 'Scrutinize Domain Scanner',
            epilog = 'Use @ to read arguments from file, e.g.: {0} @domainlist.txt'.format(sys.argv[0]),
            fromfile_prefix_chars='@',
        )
        p.add_argument('-c', '--checks',
                       nargs = '+',
                       choices = [x.__module__.replace('checks.', '') + '.' + x.__name__ for x in domainChecks],
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
                       metavar = 'example.com',
                       help = 'target domain name(s)')
        self.parser = p

    def modifyArgs(self, args):
        if args.checks:
            self.checks = [eval('checks.' + x) for x in args.checks]
        return args

def main():
    return DomainScanCLI().run()

if __name__ == '__main__':
    main()
