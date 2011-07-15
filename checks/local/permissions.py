#!/usr/bin/env python
import os
from twisted.internet import defer
from twisted.python.failure import Failure

import common
from check import LocalCheck
from err import *

readable, writable, executable = os.R_OK, os.W_OK, os.X_OK
# Files to test and "normal" permissions
UnexposedFilesMap = {
    '/etc/shadow': None,
    '/etc/passwd', readable,
    '.htpasswd': None,
    'wp-config.php': None,
]

class UnexposedFiles(LocalCheck):
    """Unexposed files"""

    def checkReadable(self, url):
        d = (getPage(url)
             .addBoth(self._cbCheckReadable)
             .addCallback(lambda readable: self.addSubresult(url, not readable)))
        return d

    def run(self):
        self.setResult(CHECK_RESULT_SUB)

        # find matches in slocate db

        # fin
        for match in matches:
            self.addSubresult(match, not )
        dl = defer.DeferredList(deferreds)
        return dl
