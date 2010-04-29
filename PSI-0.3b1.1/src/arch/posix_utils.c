/* The MIT License
 *
 * Copyright (C) 2008-2009 Floris Bruynooghe
 *
 * Copyright (C) 2008-2009 Abilisoft Ltd.
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

/* Common functions for POSIX process implementations. */

#include <Python.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>

#include "psi.h"
#include "posix_utils.h"


struct timeval
posix_timeval_subtract(struct timeval *x, struct timeval *y)
{
    struct timeval result;
    long nsec;
    
    if (x->tv_usec < y->tv_usec) {
        nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }
    result.tv_sec = x->tv_sec - y->tv_sec;
    result.tv_usec = x->tv_usec - y->tv_usec;
    return result;
}


struct timespec
posix_timespec_subtract(struct timespec *x, struct timespec *y)
{
    struct timespec result;
    long nsec;
    
    if (x->tv_nsec < y->tv_nsec) {
        nsec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
        y->tv_nsec -= 1000000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_nsec - y->tv_nsec > 1000000000) {
        nsec = (x->tv_nsec - y->tv_nsec) / 1000000000;
        y->tv_nsec += 1000000000 * nsec;
        y->tv_sec -= nsec;
    }
    result.tv_sec = x->tv_sec - y->tv_sec;
    result.tv_nsec = x->tv_nsec - y->tv_nsec;
    return result;
}


struct timespec
posix_double2timespec(const double dbl)
{
    struct timespec tspec;
    
    tspec.tv_sec = (long)dbl;
    tspec.tv_nsec = (long)(dbl-tspec.tv_sec)*1000000000;
    return tspec;
}
