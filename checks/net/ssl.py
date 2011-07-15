#!/usr/bin/env python
import os
import glob
from OpenSSL.SSL import Context
from OpenSSL.SSL import TLSv1_METHOD, VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT, OP_NO_SSLv2
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import FILETYPE_PEM, TYPE_RSA, TYPE_DSA
from twisted.internet import defer
from twisted.python.failure import Failure
from twisted.internet.ssl import ContextFactory
from twisted.web.client import getPage

import common
from check import DomainCheck
from check import HostCheck
from err import *

# Example by Glyph: http://stackoverflow.com/questions/1087227/validate-ssl-certificates-with-python/1088224#1088224
# OpenSSL Context docs: http://pyopenssl.sourceforge.net/pyOpenSSL.html/openssl-context.html
# Can use M2Crypto with Twisted to get cipher: http://www.heikkitoivonen.net/m2crypto/api/M2Crypto.SSL.TwistedProtocolWrapper-module.html

certificateAuthorityMap = {}
for certFileName in glob.glob("/etc/ssl/certs/*.pem"):
    # There might be some dead symlinks in there, so let's make sure it's real.
    if os.path.exists(certFileName):
        data = open(certFileName).read()
        x509 = load_certificate(FILETYPE_PEM, data)
        digest = x509.digest('sha1')
        # Now, de-duplicate in case the same cert has multiple names.
        certificateAuthorityMap[digest] = x509

class HTTPSGetterContextFactory(ContextFactory):

    def __init__(self, hostname, check):
        self.hostname = hostname
        self.check = check

    isClient = True

    def getContext(self):
        ctx = Context(TLSv1_METHOD)
        store = ctx.get_cert_store()
        for value in certificateAuthorityMap.values():
            store.add_cert(value)
        ctx.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT, self.verify)
        ctx.set_options(OP_NO_SSLv2)
        return ctx

    def verify(self, connection, x509, errno, depth, preverifyOK):
        commonName = x509.get_subject().commonName
        pubkey = x509.get_pubkey()
        self.check.certificates.append((
            commonName,
            x509.has_expired(),
            pubkey.bits(),
            pubkey.type(),
            errno,
            depth,
            preverifyOK,
        ))
        if preverifyOK:
            if self.check.target == commonName:
                return False
        return preverifyOK

class ProperSSL(DomainCheck):
    """Proper SSL certificate/encryption"""

    def __init__(self, *args, **kwargs):
        super(ProperSSL, self).__init__(*args, **kwargs)
        self.certificates = []
        self.hasMain = False

    def checkCertificates(self, _):
        for commonName, hasExpired, pubkeyBits, pubkeyType, errno, depth, preverifyOK in self.certificates:
            if depth == 0: # Main certificate
                self.hasMain = True
                self.addSubresult('Certificate has not expired', not hasExpired, 'Certificate has expired' if hasExpired else '')
                self.addSubresult('Certificate key is strong',
                                  not pubkeyBits < 2048,
                                  ('RSA' if pubkeyType == TYPE_RSA else 'DSA') + ' ' + \
                                  '{0} bit'.format(pubkeyBits) if not pubkeyBits < 2048 else '{0} bit is low'.format(pubkeyBits))
        self.setResult(self.hasMain, 'Unrecognized root CA, or other error' if not self.hasMain else '')

    def run(self):
        url = 'https://{0}/'.format(self.target)
        factory = HTTPSGetterContextFactory(self.target, self)
        d = (getPage(url, factory, timeout=10)
             .addBoth(self.checkCertificates))
        return d
