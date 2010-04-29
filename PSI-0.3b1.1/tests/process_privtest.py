# The MIT License
#
# Copyright (C) 2009 Floris Bruynooghe
#
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Tests for the psi.process.Process class requireing superuser privileges

The tests in this module do require superuser privileges for various
things (currently just to set the scheduling class of a test
application.

If available the tests will invoke "sudo" to gain the required
privileges, if this is not available however "su -c" will be used, but
usually you need to type in the password for each tests in that case
so this is less convenient.

Since the individual tests gain root privileges only when needed the
amount of code run as root stays to a minimum and is actually easily
auditable.  Currently only the app.c code is run as root (plus
something like priocntl or chrt - but that's OS code).
"""


import os
import unittest

from apphelper import *

try:
    import subprocess
except ImportError:
    HAVE_SUBPROCESS = False
else:
    HAVE_SUBPROCESS = True

import psi


SUDO = None
SU = None
if os.path.exists('/usr/bin/sudo'):
    SUDO = '/usr/bin/sudo'
elif os.path.exists('/bin/su'):
    SU = '/bin/su'
elif os.path.exists('/usr/bin/su'):
    SU = '/usr/bin/su'
else:
    raise RuntimeError('Neither "sudo" nor "su" found')


def rootapp(args):
    """Run a test application with root privileges

    This will invoke the application either with sudo or with su,
    returning the TestApp instance.

    args:: Argument list to run, args[0] is the command.
    """
    if SUDO:
        args.insert(0, SUDO)
        return TestApp(args)
    else:
        cmd = ['su', 'root', '-c', ' '.join(args)]
        return TestApp(cmd)


if APP32 or APP64:
    class ProcessPriorityTest(unittest.TestCase):
        def setUp(self):
            self.appname = APP32 or APP64
            self.app = None

            def tearDown(self):
                if self.app is not None:
                    self.app.kill()

        if os.uname()[0] == 'Linux':
            def test_sched_other(self):
                self.app = rootapp(['/usr/bin/chrt',
                                    '--other', '0', self.appname])
                p = psi.process.Process(self.app.pid)
                self.assertEqual(p.priority, 0)

            def test_sched_fifo(self):
                self.app = rootapp(['/usr/bin/chrt',
                                    '--fifo', '42', self.appname])
                p = psi.process.Process(self.app.pid)
                self.assertEqual(p.priority, 42)

            def test_sched_rr(self):
                self.app = rootapp(['/usr/bin/chrt',
                                    '--rr', '42', self.appname])
                p = psi.process.Process(self.app.pid)
                self.assertEqual(p.priority, 42)

        if os.uname()[0] == 'SunOS':
            def test_class_ts(self):
                # This is a very bad class to test, we can't really
                # assert anything since psi gets the real priority and
                # not the user priority.  But on SunOS 8 the FX class
                # is not available, so better have this test then none.
                self.app = rootapp(['/usr/bin/priocntl', '-e',
                                    '-c', 'TS', self.appname])
                p = psi.process.Process(self.app.pid)
                self.assertTrue(-60 <= p.priority <= 60,
                                '-60 <= %d <= 60' % p.priority)

            if psi.arch.arch_type().release_info > (5,8):
                def test_class_fx(self):
                    self.app = rootapp(['/usr/bin/priocntl', '-e',
                                        '-c', 'FX', '-m', '60',
                                        '-p', '42', self.appname])
                    p = psi.process.Process(self.app.pid)
                    self.assertEqual(p.priority, 42)

        if os.uname()[0] == 'AIX':
            def test_aixapp(self):
                # aixapp runs under SCHED_RR at priority 42.
                aixapp = os.path.join(os.path.dirname(__file__), 'aixapp')
                self.app = rootapp([aixapp])
                p = psi.process.Process(self.app.pid)
                self.assertEqual(p.priority, 42)
