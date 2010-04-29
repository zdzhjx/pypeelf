/* The MIT License
 *
 * Copyright (C) 2009 Floris Bruynooghe
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* AIX implementation of the _psi functions */


#include <Python.h>

#include <libperfstat.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <time.h>
#include <utmpx.h>

#include "psi.h"
#include "psifuncs.h"
#include "posix_utils.h"


/* XXX The find_utmpx_boottime, arch_boottime and arch_uptime code is exactly
 *     the same as for SunOS.  This needs to be merged. */


/* Local definitions */
static int find_utmpx_boottime(void);


/* Global variable for caching, need to read utmp only once. */
static struct timeval utmpx_boottime = {0, 0};


/***** Public functions *****/


int
arch_boottime(struct timespec *boottime)
{
    if (utmpx_boottime.tv_sec == 0 && utmpx_boottime.tv_usec == 0)
        if (find_utmpx_boottime() < 0)
            return -1;
    boottime->tv_sec = utmpx_boottime.tv_sec;
    boottime->tv_nsec = utmpx_boottime.tv_usec * 1000;
    return 0;
}


struct loadavginfo *
arch_loadavginfo(void)
{
    struct loadavginfo *loadi;
    perfstat_cpu_total_t cpu_stats;
    int r;

    r = perfstat_cpu_total(NULL, &cpu_stats, sizeof(perfstat_cpu_total_t), 1);
    if (r < 0)
        return (struct loadavginfo*)PyErr_SetFromErrno(PyExc_SystemError);
    loadi = psi_calloc(sizeof(struct loadavginfo));
    if (loadi == NULL)
        return NULL;
    loadi->one = cpu_stats.loadavg[0] / (double)(1 << SBITS);
    loadi->five = cpu_stats.loadavg[0] / (double)(1 << SBITS);
    loadi->fifteen = cpu_stats.loadavg[0] / (double)(1 << SBITS);
    loadi->loadavg_status = PSI_STATUS_OK;
    return loadi;
}


int
arch_uptime(struct timespec *uptime)
{
    struct timeval now;
    struct timeval ut;

    if (utmpx_boottime.tv_sec == 0 && utmpx_boottime.tv_usec == 0)
        if (find_utmpx_boottime() < 0)
            return -1;
    if (gettimeofday(&now, NULL) < 0) {
        PyErr_SetFromErrno(PyExc_SystemError);
        return -1;
    }
    ut = posix_timeval_subtract(&now, &utmpx_boottime);
    uptime->tv_sec = ut.tv_sec;
    uptime->tv_nsec = ut.tv_usec * 1000;
    return 0;
}


/***** Local functions *****/


/** Find the boottime from the utmpx database
 *
 * The boottime is stored in the global varialbe `utmpx_boottime'.  If this
 * variable is set to {0, 0} you still have to call this function, if it has
 * another value calling this function will just waste CPU cycles.
 */
static int
find_utmpx_boottime(void)
{
    struct utmpx *uti;
    struct utmpx id;

    uti = getutxent();
    if (uti == NULL) {
        PyErr_SetString(PyExc_SystemError, "Failed to open utmpx database");
        return -1;
    }
    setutxent();
    id.ut_type = BOOT_TIME;
    uti = getutxid(&id);
    if (uti == NULL) {
        endutxent();
        PyErr_SetString(PyExc_SystemError,
                        "Failed to find BOOT_TIME in utmpx database");
        return -1;
    }
    utmpx_boottime.tv_sec = uti->ut_tv.tv_sec;
    utmpx_boottime.tv_usec = uti->ut_tv.tv_usec;
    endutxent();
    return 0;
}
