from libprobe.probe import Probe
from lib.check.eventlog import check_eventlog
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = {
        'eventlog': check_eventlog
    }

    probe = Probe("eventlog", version, checks)

    probe.start()
