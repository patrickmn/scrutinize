import socket
from twisted.internet import error

import config
from err import *

class Result(object):

    def __init__(self, text=None, status=CHECK_DEFAULT, extra=None, failure=None):
        self.status = status
        self.text = text
        self.extra = extra
        self.failure = failure
        self.check = None

class Check(object):

    def __init__(self, target):
        self.target = target
        self.result = Result()
        self.result.check = self
        self.subresults = []

    def setResult(self, status, extra=None, failure=None):
        self.result.status = status
        if config.useCheckClassNames:
            self.result.text = '{0.__module__}.{0.__name__}'.format(self.__class__)
        else:
            self.result.text = self.__doc__
        self.result.extra = extra
        self.result.failure = failure
        self.result = self.translateResult(self.result)

    def addSubresult(self, text, status, extra=None, failure=None):
        result = Result(text, status, extra, failure)
        result.check = self
        result = self.translateResult(result)
        self.subresults.append(result)

    def translateResult(self, result):
        if result.failure and not result.extra:
            if result.failure.type == error.TimeoutError:
                result.extra = "Timeout"
            elif result.failure.type == socket.gaierror:
                result.extra = "Can't connect"
            else:
                result.extra = result.failure.getErrorMessage()
        return result

    def run(self):
        pass

class DomainCheck(Check):
    pass

class HostCheck(Check):
    pass
