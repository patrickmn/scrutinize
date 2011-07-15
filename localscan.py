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
from scanner import LocalScanner
from err import ScrutinizeException
from color import colorize

import checks.local.blah
localChecks = (
    checks.local.blah.bloo,
)

class LocalScanCLI(BaseCLI):

    def __init__(self):
        super(LocalScanCLI, self).__init__()
        self.scanner = LocalScanner
        self.checks = localChecks

        p = ArgParser(
            description = 'Scrutinize Local Scanner',
            fromfile_prefix_chars='@',
        )
        p.add_argument('-c', '--checks',
                       nargs = '+',
                       choices = [x.__module__.replace('checks.', '') + '.' + x.__name__ for x in localChecks],
                       metavar = ('local.blah.Bloo', 'local.blah.Blyy'),
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
        self.parser = p

    def modifyArgs(self, args):
        if args.checks:
            self.checks = [eval('checks.' + x) for x in args.checks]
        return args

def main():
    return LocalScanCLI().run()

if __name__ == '__main__':
    main()
