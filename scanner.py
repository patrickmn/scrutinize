from twisted.internet import defer

import config
import log
from color import colorize
from err import *

class Scanner(object):

    def __init__(self, target, checks, title=None, verbose=False, runningResults=False):
        self.target = target
        self.checks = checks
        self.title = title
        self.scans = []
        self.verbose = verbose
        self.runningResults = runningResults

    def __repr__(self):
        return "<Scanner({0.target}, {0.title}, v={0.verbose})>".format(self)

    def checkFinished(self, check):
        if self.runningResults:
            self.showResult(check.result)

    def showResult(self, result):
        # TODO: RESULT_SUB master results should be shown with warningsOnly on!
        output = self.formatResult(result)
        if output:
            print(output)
        for subresult in result.check.subresults:
            output = self.formatResult(subresult, sub=True)
            if output:
                print(output)

    def showResults(self):
        if not self.runningResults:
            if config.warningsOnly:
                hasWarning = False
                for scan in self.scans:
                    if not scan.result.status:
                        hasWarning = True
                    for subresult in scan.subresults:
                        if not subresult.status:
                            hasWarning = True
                if not hasWarning:
                    return
            print("")
            print(colorize("@W{0}@x".format(self.title)))
            print(config.bar)
            for scan in self.scans:
                self.showResult(scan.result)
            print("")

    def formatResult(self, result, sub=False):
        if result.extra:
            extra = colorize('@B--@x ') + result.extra
        else:
            extra = ''
        if not result.status:
            last = colorize('@B[@R!!!@B]@x')
        elif config.warningsOnly:
            return
        elif result.status == CHECK_NOT_APPLICABLE:
            last = '@B[@D - @B]@x'
        elif result.status == CHECK_RESULT_HIDDEN:
            last = ''
        elif result.status == CHECK_RESULT_SUB:
            last = colorize('@B[---]@x')
        elif result.status == CHECK_RESULT_UNCERTAIN:
            last = colorize('@B[@Y ? @B]@x')
        else:
            last = colorize('@B[ @G- @B]@x')
        if sub:
            output = colorize("   @y-@x {0:49} {1}{2}".format(result.text, last, extra))
        else:
            output = colorize(" @Y*@x {0:51} {1}{2}".format(result.text, last, extra))
        return output

    def run(self):
        if self.runningResults:
            print("")
            print(colorize("@W{0}@x".format(self.title)))
            print(config.bar)
        for check in self.checks:
            c = check(self.target)

            # "lambda x: c, x" takes the (same) c in scope each loop; we have to do
            # manual assignment to get the current c.
            def checkFinishedTrigger(value, c=c):
                self.checkFinished(c)

            d = (c.run()
                 .addBoth(checkFinishedTrigger))
            c.deferred = d
            self.scans.append(c)
        dl = (defer.DeferredList([c.deferred for c in self.scans])
              .addCallback(lambda x: self.showResults())
              .addErrback(log.err)) # Uncaught error
        return dl

class DomainScanner(Scanner):
    pass

class HostScanner(Scanner):
    pass

class LocalScanner(Scanner):
    pass
