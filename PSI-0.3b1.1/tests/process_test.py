# The MIT License
#
# Copyright (C) 2007 Chris Miles
#
# Copyright (C) 2008-2009 Floris Bruynooghe
#
# Copyright (C) 2008-2009 Abilisoft Ltd.
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

"""Tests for the psi.process.Process class"""


import datetime
import grp
import math
import os
import pwd
import sys
import unittest

from apphelper import *

try:
    import subprocess
except ImportError:
    HAVE_SUBPROCESS = False
else:
    HAVE_SUBPROCESS = True

import psi


# Patch old versions of unittest
if not hasattr(unittest.TestCase, 'assertTrue'):
    unittest.TestCase.assertTrue = unittest.TestCase.failUnless
if not hasattr(unittest.TestCase, 'assertFalse'):
    unittest.TestCase.assertFalse = unittest.TestCase.failIf
if not hasattr(unittest.TestCase, 'assertAlmostEqual'):
    def assertAlmostEqual(self, first, second, places=7, msg=None):
        """Stolen from Python 2.5"""
        if round(second-first, places) != 0:
            raise self.failureException(
                msg or '%r != %r within %r places'
                % (first, second, places))
    unittest.TestCase.assertAlmostEqual = assertAlmostEqual


class ProcessInitTest(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)

    def test_type(self):
        self.assert_(isinstance(self.p, psi.process.Process))

    def test_bad_kw_arg(self):
        self.assertRaises(TypeError, psi.process.Process, foo=1)

    def test_bad_pos_arg(self):
        self.assertRaises(TypeError, psi.process.Process, 'foo')

    def test_no_such_pid(self):
        # may not work in rare circumstances ... see how we go
        self.assertRaises(ValueError, psi.process.Process, pid=-1)

    def test_pid(self):
        self.assertEqual(self.p.pid, self.pid)


class ProcessSpecialMethods(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)

    def test_repr(self):
        self.assertEqual('psi.process.Process(pid=%d)'%self.pid, repr(self.p))

    def test_hash_works(self):
        self.assertTrue(hash(self.p))

    def test_hash_compare(self):
        p = psi.process.Process(self.pid)
        self.assertEqual(hash(self.p), hash(p))


class RichCompareTest(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)
        self.init = psi.process.Process(1)

    def test_eq(self):
        self.assertEqual(self.p, self.p)
        self.assertEqual(self.p, psi.process.Process(self.pid))

    def test_ne(self):
        self.assertNotEqual(self.p, self.pid)
        self.assertNotEqual(self.p, self.init)

    def test_lt(self):
        self.assertTrue(self.init < self.p)
        self.assertFalse(self.p < self.p)
        self.assertFalse(self.p < self.init)

    def test_le(self):
        self.assertTrue(self.init <= self.p)
        self.assertTrue(self.p <= self.p)
        self.assertFalse(self.p <= self.init)

    def test_gt(self):
        self.assertFalse(self.init > self.p)
        self.assertFalse(self.p > self.p)
        self.assertTrue(self.p > self.init)

    def test_ge(self):
        self.assertFalse(self.init >= self.p)
        self.assertTrue(self.p >= self.p)
        self.assertTrue(self.p >= self.init)


class ProcessExeArgsEnvTest(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)
        self.arch = psi.arch.arch_type()
        self.args_short = ['abcdefghijklmnopqrtstuvw']
        self.args_long = 50 * self.args_short
        self.env = {'foo': 'fooenv',
                    'bar': 'barenv',
                    'baz': 'bazenv'}
        self.app = None

    def tearDown(self):
        if self.app is not None:
            self.app.kill()

    if hasattr(psi.process.Process, 'accounting_name'):
        def test_accounting_name(self):
            self.assertEqual(self.p.accounting_name,
                             os.path.basename(sys.executable))

    def test_exe(self):
        if os.uname()[0] == 'Linux':
            self.assertTrue(os.path.isabs(self.p.exe))
        elif os.uname()[0] == 'Darwin':
            self.assertEqual(self.p.exe, sys.executable)
        else: 
            self.assertTrue(self.p.exe.find('python') >= 0) 

    def test_args_simple(self):
        self.assert_('python' ' '.join(self.p.args).lower())

    def test_argc_simple(self):
        self.assertTrue(self.p.argc > len(sys.argv))

    def test_command(self):
        calc_comm = ' '.join(self.p.args)
        psi_comm = self.p.command
        self.assertEqual(psi_comm, calc_comm[:len(psi_comm)])

    def test_env_simple(self):
        self.assertEqual(self.p.env['USER'], os.getlogin())


    if APP32:
        def test_env_32bit(self):
            self.app = TestApp([APP32], env=self.env)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.env, self.env)

        def test_args_32bit_short(self):
            self.app = TestApp([APP32] + self.args_short)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.args, tuple([APP32] + self.args_short))

        def test_args_32bit_long(self):
            self.app = TestApp([APP32] + self.args_long)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.args, tuple([APP32] + self.args_long))

        def test_args_32bit_longarg(self):
            args = [APP32, 'arg_longer_then_fifty_characters'*2]
            self.app = TestApp(args)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.args[1], args[1])

        def test_argc_32bit(self):
            self.app = TestApp([APP32, 'foo', 'bar'])
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.argc, 3)

    if APP64:
        def test_env_64bit(self):
            self.app = TestApp([APP64], env=self.env)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.env, self.env)

        def test_args_64bit_short(self):
            self.app = TestApp([APP64] + self.args_short)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.args, tuple([APP64] + self.args_short))

        def test_args_64bit_long(self):
            self.app = TestApp([APP64] + self.args_long)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.args, tuple([APP64] + self.args_long))

        def test_args_64bit_longarg(self):
            args = [APP64, 'arg_longer_then_fifty_characters'*2]
            self.app = TestApp(args)
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.args[1], args[1])

        def test_argc_64bit(self):
            self.app = TestApp([APP64] + ['foo', 'bar'])
            p = psi.process.Process(self.app.pid)
            self.assertEqual(p.argc, 3)


class ProcessIdsTest(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)

    def test_euid(self):
        self.assertEqual(self.p.euid, os.geteuid())

    def test_egid(self):
        self.assertEqual(self.p.egid, os.getegid())

    def test_ruid(self):
        self.assertEqual(self.p.ruid, os.getuid())

    def test_rgid(self):
        self.assertEqual(self.p.rgid, os.getgid())


class ProcessAttrsTest(unittest.TestCase):
    def setUp(self):
        self.arch = psi.arch.arch_type()
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)

    if hasattr(psi.process.Process, 'cwd'):
        if os.uname()[0] == 'Darwin':
            def test_cwd_exception(self):
                self.assertRaises(psi.AttrNotImplementedError,
                                  getattr, self.p, 'cwd')
        else:
            def test_cwd(self):
                self.assertEqual(os.path.normpath(self.p.cwd),
                                 os.path.dirname(os.path.dirname(__file__)))

    def test_ppid(self):
        self.assert_(self.p.ppid > 1)
        self.assertEqual(type(self.p.ppid), type(self.p.pid))

    def test_pgrp(self):
        pgrp = pscmd('pgrp')
        self.assertEqual(self.p.pgrp, int(pgrp))

    def test_sid(self):
        sid = pscmd('sid')
        self.assertEqual(self.p.sid, int(sid))

    def test_nthreads(self):
        if isinstance(self.arch, psi.arch.ArchLinux) \
                and self.arch.release[:3] == '2.4':
            return
        if isinstance(self.arch, psi.arch.ArchSunOS):
            nlwp = pscmd('nlwp')
            self.assertEqual(self.p.nthreads, int(nlwp))
        else:
            self.assertEqual(self.p.nthreads, 1)

    def test_terminal(self):
        if isinstance(self.arch, psi.arch.ArchSunOS) \
                and self.arch.release in ['5.8', '5.9']:
            return
        if not HAVE_SUBPROCESS:
            return

        terminal = subprocess.Popen(['/usr/bin/tty'],
                                    stdout=subprocess.PIPE).communicate()[0]
        terminal = terminal.decode()
        self.assertEqual(self.p.terminal, terminal.strip())

    def test_status(self):
        if isinstance(self.arch, psi.arch.ArchLinux):
            self.assertEqual(self.p.status, psi.process.PROC_STATUS_RUNNING)
        elif isinstance(self.arch, psi.arch.ArchSunOS):
            if hasattr(psi.process, 'PROC_STATUS_SONPROC'):
                self.assertEqual(self.p.status, psi.process.PROC_STATUS_SONPROC)
            else:
                self.assertEqual(self.p.status, psi.process.PROC_STATUS_SRUN)
        elif isinstance(self.arch, psi.arch.ArchAIX):
            self.assertEqual(self.p.status, psi.process.PROC_STATUS_SACTIVE)

    def test_nice(self):
        # XXX Also need to test non-default nice values.
        ni = pscmd('ni')
        self.assertEqual(self.p.nice, int(ni))


class ProcessPriorityTest(unittest.TestCase):
    if os.uname()[0] == 'AIX':
        def test_range(self):
            p = psi.process.Process(os.getpid())
            self.assertTrue(0 <= p.priority <= 255)

    # XXX Add tests_range like tests for Linux and SunOS.


class ProcessTimeTest(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)

    def test_start_time(self):
        # Due to rounding errors and CPUs being able to do lots within
        # just one jiffie/tick it can appear that we started after
        # now, at least on Linux.
        self.assert_(isinstance(self.p.start_time, datetime.datetime))
        now = datetime.datetime.utcnow() + datetime.timedelta(seconds=1)
        assert now >= self.p.start_time, '%s >= %s' % (now, self.p.start_time)


class ProcessCpuTest(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)

    def test_cputime(self):
        self.assert_(isinstance(self.p.cputime, datetime.timedelta))
        self.assert_(self.p.cputime >= datetime.timedelta(0))

    def test_utime(self):
        self.assert_(isinstance(self.p.utime, datetime.timedelta))
        self.assert_(self.p.utime >= datetime.timedelta(0))

    def test_stime(self):
        self.assert_(isinstance(self.p.stime, datetime.timedelta))
        self.assert_(self.p.stime >= datetime.timedelta(0))

    def test_cputime_sum(self):
        variance = datetime.timedelta(seconds=1)
        min = self.p.cputime - variance
        max = self.p.cputime + variance
        assert min < self.p.utime+self.p.stime < max, \
            '%s < %s < %s' % (min, self.p.utime+self.p.stime, max)

    if hasattr(psi.process.Process, 'pcpu'):
        def test_pcpu(self):
            self.assertTrue(0 <= self.p.pcpu <= 100)


class ProcessMemTest(unittest.TestCase):
    def setUp(self):
        self.pid = os.getpid()
        self.p = psi.process.Process(self.pid)
        self.arch = psi.arch.arch_type()

    def test_rss(self):
        self.assert_(self.p.rss > 0)

    def test_vsz(self):
        self.assert_(self.p.vsz > 0)

    def test_rss_vs_vsz(self):
        if isinstance(self.arch, psi.arch.ArchAIX):
            # On AIX the VSZ is only the data section of the virtual
            # size since that's what ps(1) does there.  This means
            # that often (but not always) the RSS value will be larger
            # then the VSZ value, depending on the amount of data in
            # the shared libraries.
            return
        self.assert_(self.p.rss < self.p.vsz,
                     "%d < %d" % (self.p.rss, self.p.vsz))

    def test_rss_ps(self):
        rss = int(pscmd('rssize'))
        rss_min = rss - rss*0.1
        rss_max = rss + rss*0.1
        self.assert_(rss_min < self.p.rss/1024 < rss_max,
                     '%s < %s < %s' % (rss_min, self.p.rss/1024, rss_max))

    def test_vsz_ps(self):
        vsz = int(pscmd('vsz'))
        self.assert_(vsz*0.8 < self.p.vsz/1024 < vsz*1.2,
                     '%s < %s < %s' % (vsz*0.8, self.p.vsz/1024, vsz*1.2))


class ConstantsTest(unittest.TestCase):
    def test_status_codes(self):
        stat_names = [s for s in dir(psi.process)
                      if s.startswith('PROC_STATUS_')]
        self.assert_(len(stat_names) > 0)
        for name in stat_names:
            attr = getattr(psi.process, name)
            self.assert_(isinstance(attr, int))


class ProcessPrivsTest(unittest.TestCase):
    def test_init_works(self):
        p = psi.process.Process(1)
        self.assertEqual(p.euid, 0)


if __name__ == '__main__':
    unittest.main()
