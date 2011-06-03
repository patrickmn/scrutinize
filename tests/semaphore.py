import warnings
from twisted.trial import unittest
from twisted.internet import defer
from twisted.internet import reactor

import common

class TestSemMap(unittest.TestCase):

    def test_semMap(self):
        self.stuff = ['hi', 'there', 'how', 'are', 'you', 'doing']
        self.got = []
        # Apply getter to all items in self.stuff, each time with
        # arg forReal True and kwarg noSeriously True.
        dl = (common.semMap(self.getter, self.stuff, True, noSeriously=True)
              .addCallback(self.validate))
        return dl

    def getter(self, x, forReal=False, noSeriously=False):
        if forReal and noSeriously:
            self.got.append(x)

        d = defer.Deferred()
        reactor.callLater(0, d.callback, "success")
        return d

    def validate(self, _):
        self.assertTrue(
            len(self.got) == len(self.stuff) and
            set(self.got).issubset(set(self.stuff)))
