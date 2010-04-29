"""Check for memory leak

If the memory goes consistent and significantly up there is a leak,
either directly or from reference counting errors.
"""


import datetime
import time
import os

import psi


pid = os.getpid()
print 'pid:', os.getpid()
p = psi.process.Process(os.getpid())
startrss = p.rss
starttime = datetime.datetime.now()
tdiff = datetime.datetime.now() - starttime
n = 0


while tdiff.seconds < 15:
    o = psi.arch.ArchBase()
    p = psi.process.Process(pid)
    r = psi.process.ProcessTable()
    s = psi.loadavg()
    tdiff = datetime.datetime.now() - starttime
    print 'time: %(time)s rss: %(rss)s (%(pct)s%%)' \
        % {'rss': p.rss,
           'pct': p.rss*100/startrss,
           'time': str(tdiff).split('.')[0]}
    n += 1
    time.sleep(0.001)


p = psi.process.Process(os.getpid())
print 'n=%(n)d - rss: %(rss)s (%(pct)s%%)' \
    % {'rss': p.rss,
       'pct': p.rss*100/startrss,
       'n': n}
