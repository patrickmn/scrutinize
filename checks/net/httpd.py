#!/usr/bin/env python
import os
import socket
from twisted.internet import defer
from twisted.python.failure import Failure
from twisted.web.client import getPage

import common
from check import DomainCheck
from check import HostCheck
from err import *

configurationFiles = [
    '.htaccess',
    '.htpasswd',
    'nginx.conf',
    'wp-config.php',
]

class UnexposedFiles(DomainCheck):
    """Unexposed files"""

    def _cbCheckReadable(self, result):
        return result and not isinstance(result, Failure)

    def checkReadable(self, url):
        d = (getPage(url)
             .addBoth(self._cbCheckReadable)
             .addCallback(lambda readable: self.addSubresult(url, not readable)))
        return d

    def run(self):
        self.setResult(CHECK_RESULT_SUB)
        deferreds = []
        for file in configurationFiles:
            deferreds.append(self.checkReadable('http://{0}/{1}'.format(self.target, file)))
        dl = defer.DeferredList(deferreds)
        return dl
