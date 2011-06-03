import os
import sys
from twisted.internet import reactor
from twisted.internet import defer
from twisted.internet.error import ReactorNotRunning
from argparse import ArgumentParser

import config
import log
import common
import scanner

class ArgParser(ArgumentParser):

    # Parse arguments from file (multiple args per line)
    def convert_arg_line_to_args(self, arg_line):
        for arg in arg_line.split():
            if not arg.strip():
                continue
            yield arg

class BaseCLI(object):

    def __init__(self):
        self.parser = None
        self.args = None
        self.scanner = None
        self.checks = []
        self.chunks = []
        self.addressTitles = {}

    def parseArgs(self):
        return self.parser.parse_args()

    def modifyArgs(self, args):
        return args

    def applyArgs(self, args):
        config.color = args.color
        config.warningsOnly = args.warnings_only
        config.throttle = args.throttle
        config.useCheckClassNames = args.useCheckClassNames
        if args.verbose:
            log.startLogging(sys.stdout)
        self.chunks = list(common.chunks(args.addresses, 100))
        self.args = args

    def runScanners(self):
        scanners = []
        single = len(self.args.addresses) == 1
        for address in self.chunks.pop(0):
            title = self.addressTitles.get(address) or address
            scanner = self.scanner(address, checks=self.checks, title=title, verbose=self.args.verbose, runningResults=single)
            scanners.append(scanner)
        dl = (defer.DeferredList([scanner.run() for scanner in scanners])
              .addCallback(self._cbRunScanners))
        return dl

    def _cbRunScanners(self, _):
        if self.chunks:
            return self.runScanners()

    def run(self):
        args = self.parseArgs()
        d = (defer.maybeDeferred(self.modifyArgs, args)
             .addCallback(self.applyArgs)
             .addCallback(lambda x: self.runScanners())
             .addCallback(lambda x: self.stop()))
        reactor.run()
        return d

    def stop(self):
        try:
            reactor.stop()
        except ReactorNotRunning:
            pass
