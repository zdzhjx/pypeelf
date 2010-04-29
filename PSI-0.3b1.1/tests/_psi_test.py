# The MIT License
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


import datetime
import os
import time
import unittest

import psi


class ExceptionsTests(unittest.TestCase):
    def test_subclass(self):
        self.assert_(issubclass(psi.AttrNotAvailableError, AttributeError))
        self.assert_(issubclass(psi.AttrInsufficientPrivsError, AttributeError))
        self.assert_(issubclass(psi.AttrNotImplementedError, AttributeError))

    def test_instances(self):
        na = psi.AttrNotAvailableError()
        ip = psi.AttrInsufficientPrivsError()
        ni = psi.AttrNotImplementedError()
        self.assert_(isinstance(na, AttributeError))
        self.assert_(isinstance(ip, AttributeError))
        self.assert_(isinstance(ni, AttributeError))


class LoadavgTests(unittest.TestCase):
    def test_type(self):
        loadavg = psi.loadavg()
        self.failUnless(isinstance(loadavg, tuple))

    def test_len(self):
        loadavg = psi.loadavg()
        self.assertEqual(len(loadavg), 3)

    def test_value_types(self):
        loadavg = psi.loadavg()
        for v in loadavg:
            self.failUnless(isinstance(v, float))

    def test_values(self):
        psiavg = psi.loadavg()
        if hasattr(os, 'getloadavg'):
            osavg = os.getloadavg()
            for i, j in zip(psiavg, osavg):
                self.assertAlmostEqual(i, j)
        else:
            for l in psiavg:
                self.assert_(0.0 <= l < 1000.0, '0.0 < %f < 1000.0'%l)


class BoottimeTests(unittest.TestCase):
    def test_datetime(self):
        bt = psi.boottime()
        assert isinstance(bt, datetime.datetime)

    def test_gt_epoch(self):
        epoch = datetime.datetime(1970, 1, 1)
        bt = psi.boottime()
        assert bt > epoch, '%s > %s' % (bt, epoch)

    def test_lt_now(self):
        bt = psi.boottime()
        now = datetime.datetime.utcnow()
        assert bt < now


class UptimeTests(unittest.TestCase):
    def test_timedelta(self):
        ut = psi.uptime()
        assert isinstance(ut, datetime.timedelta)

    def test_uptime_gt_null(self):
        assert psi.uptime() > datetime.timedelta(0)

    def test_uptime_calc(self):
        psi_uptime = psi.uptime()
        calc_uptime = datetime.datetime.utcnow() - psi.boottime()
        calc_min = calc_uptime - datetime.timedelta(seconds=2)
        calc_max = calc_uptime + datetime.timedelta(seconds=2)
        assert calc_min < psi_uptime < calc_max, \
            "%s < %s < %s" % (calc_min, psi_uptime, calc_max)


if hasattr(psi, 'getzoneid'):
    class SolarisZonesTests(unittest.TestCase):
        def test_getzoneid(self):
            id = psi.getzoneid()
            self.assert_(0 >= id)

        def test_getzonenamebyid(self):
            name = psi.getzonenamebyid(0)
            self.assertEqual(name, 'global')

        def test_getzonenamebyid_exception(self):
            self.assertRaises(ValueError, psi.getzonenamebyid, -1)

        def test_getzoneidbyname(self):
            id = psi.getzoneidbyname('global')
            self.assertEqual(id, 0)

        def test_getzoneidbyname_exception(self):
            # XXX This is brittle.
            self.assertRaises(ValueError, psi.getzoneidbyname, 'foobar')


if __name__ == '__main__':
    unittest.main()
