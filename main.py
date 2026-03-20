from libprobe.probe import Probe
from lib.check.eventlog import CheckEventlog
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = (
        CheckEventlog,
    )

    probe = Probe("eventlog", version, checks, loggers=('aiowmi',))
    probe.start()
