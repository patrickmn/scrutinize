import warnings
from twisted.trial import unittest
from twisted.internet import defer
from twisted.internet import reactor

import common
import scanner
import domainscan
import hostscan
import config

class TestDomainScan(unittest.TestCase):

    def setUp(self):
        config.warningsOnly = True

    def test_domainScanOne(self):
        d = scanner.DomainScanner('google.com', title='google.com', checks=domainscan.domainChecks[0]).run()
        return d

    test_domainScanOne.skip = "Fix it"

    def test_domainScanFull(self):
        d = scanner.DomainScanner('google.com', title='google.com', checks=domainscan.domainChecks).run()
        return d

    test_domainScanFull.skip = "Fix it"

    def test_domainScanFullMultiple(self):
        dl = defer.DeferredList(
            scanner.DomainScanner('google.com', title='google.com', checks=domainscan.domainChecks).run(),
            scanner.DomainScanner('bing.com', title='google.com', checks=domainscan.domainChecks).run())
        return dl

    test_domainScanFullMultiple.skip = "Fix it"

class TestHostScan(unittest.TestCase):

    def setUp(self):
        config.warningsOnly = True

    def test_hostScanOne(self):
        d = scanner.HostScanner('209.85.149.106', checks=hostscan.hostChecks[0]).run()
        return d

    test_hostScanOne.skip = "Fix it"

    def test_hostScanFull(self):
        d = scanner.HostScanner('209.85.149.106', checks=hostscan.hostChecks).run()
        return d

    test_hostScanFull.skip = "Fix it"

    def test_hostScanFullMultiple(self):
        dl = defer.DeferredList(
            scanner.HostScanner('209.85.149.106', checks=hostscan.hostChecks).run(),
            scanner.HostScanner('65.55.175.254', checks=hostscan.hostChecks).run())
        return dl

    test_hostScanFullMultiple.skip = "Fix it"
