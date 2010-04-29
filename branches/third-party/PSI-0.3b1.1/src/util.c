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

#include <Python.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "psi.h"


/***** Global Variables *****/
PyObject *FROMTIMESTAMP = NULL; /* datetime.datetime.utcfromtimestamp */
PyObject *TIMEDELTA = NULL;     /* datetime.timedelta */


/***** Functions *****/


int
psi_checkattr(const char *name, const int status)
{
    if (status == PSI_STATUS_OK)
        return 0;
    else if (status == PSI_STATUS_NI)
        PyErr_Format(PsiExc_AttrNotImplementedError,
                     "%s is not implemented on this system", name);
    else if (status == PSI_STATUS_NA)
        PyErr_Format(PsiExc_AttrNotAvailableError,
                     "%s is not available for this process", name);
    else if (status == PSI_STATUS_PRIVS)
        PyErr_Format(PsiExc_AttrInsufficientPrivsError,
                     "Insufficient privileges for %s", name);
    return -1;
}


void *
psi_malloc(size_t size)
{
    void *value;

#ifdef PYMALLOC
    value = PyMem_Malloc(size);
#else
    value = malloc(size);
#endif
    if (value == NULL)
        PyErr_NoMemory();
    return value;
}


void *
psi_realloc(void *ptr, size_t size)
{
    void *value;

#ifdef PYMALLOC
    value = PyMem_Realloc(ptr, size);
#else
    value = realloc(ptr, size);
#endif
    if (value == NULL)
        PyErr_NoMemory();
    return value;
}


void
psi_free(void *ptr)
{
#ifdef PYMALLOC
    PyMem_Free(ptr);
#else
    free(ptr);
#endif
}


void *
psi_calloc(size_t size)
{
    void *value;

    value = psi_malloc(size);
    if (value == NULL)
        return NULL;
    memset(value, 0, size);
    return value;
}


char *
psi_strdup(const char *str)
{
    char *to;

    to = psi_malloc((size_t)(strlen(str)+1));
    if (to == NULL)
        return NULL;
    return strcpy(to, str);
}


char *
psi_strndup(const char *str, size_t n)
{
    char *to;

    to = psi_malloc((size_t)(n+1));
    if (to == NULL)
        return NULL;
    to[n] = '\0';
    return strncpy(to, str, n);
}


int
psi_asprintf(char **ptr, const char *template, ...)
{
    va_list ap;
    int r;
    size_t size = 128;
    char *ptr2;

    *ptr = (char *)malloc(size);
    if (*ptr == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    va_start(ap, template);
    r = PyOS_vsnprintf(*ptr, size, template, ap);
    va_end(ap);
    if (r < 0) {
        free(*ptr);
        *ptr = NULL;
        PyErr_Format(PyExc_SystemError,
                     "PyOS_vsnprintf returned error code: %d", r);
        return -1;
    }
    else if (r > (int)size) {
        size = (size_t)r + 1;
        ptr2 = (char *)realloc(*ptr, size);
        if (ptr2 == NULL) {
            free(*ptr);
            ptr = NULL;
            PyErr_NoMemory();
            return -1;
        }
        *ptr = ptr2;
        va_start(ap, template);
        r = PyOS_vsnprintf(*ptr, size, template, ap);
        va_end(ap);
        if (r < 0 || r > (int)size) {
            free(*ptr);
            *ptr = NULL;
            if (r < 0)
                PyErr_Format(PyExc_SystemError,
                             "PyOS_vsnprintf returned error code: %d", r);
            else
                PyErr_SetString(PyExc_SystemError,
                                "Required size from PyOS_vsnprintf was wrong!");
            return -1;
        }
    }
    return size;
}


int
psi_read_file(char **buf, char *path)
{
    void *ptr;
    int bufsize = 2048;
    int fd;
    int n;

    errno = 0;
    fd = open(path, O_RDONLY, 0);
    if (fd == -1) {
        if (errno == EACCES)
            return -2;
        else if (errno == ENOENT) {
            PyErr_SetFromErrnoWithFilename(PyExc_ValueError, path);
            return -1;
        } else {
            PyErr_SetFromErrnoWithFilename(PyExc_SystemError, path);
            return -1;
        }
    }
    *buf = (char*) psi_malloc(bufsize);
    if (*buf == NULL)
        return -1;
    while ((n = read(fd, *buf, bufsize)) > 0) {
        if (n < bufsize)
            break;
        bufsize += 2048;
        ptr = psi_realloc(*buf, bufsize);
        if (ptr == NULL) {
            psi_free(*buf);
            return -1;
        }
        *buf = (char*) ptr;
        lseek(fd, 0, SEEK_SET);
    }
    close(fd);
    if (n == -1) {		/* read error */
        psi_free(*buf);
        return -2;              /* XXX: Should be more specific here */
    }
    return n;
}


/** Read a link and allocate space for the string automtically
 *
 * This will allocate the space for the target string using psi_malloc(), call
 * psi_free() on it when you're done.
 *
 * The result will be stored in `target' and will be `\0' terminated.
 *
 * The `link' parameter is really `const' but PyErr_SetFromErrnoWithFilename
 * is not declared as such.
 *
 * XXX Consider setting *target to NULL in case of failure, now it will most
 *     likely point to some free memory (unless the first psi_malloc() fails
 *     in which case it will point to NULL).
 *
 * @return -1 on an error, -2 on not found or no privs, 0 on success.
 */
int
psi_readlink(char **target, char *link)
{
    void *ptr;
    size_t size = 128;
    int r;

    *target = (char *)psi_malloc(size);
    if (*target == NULL)
        return -1;
    errno = 0;
    r = readlink(link, *target, size-1);
    while ((size_t)r == size-1) {
        size += 128;
        ptr = (char *)psi_realloc(*target, size);
        if (ptr == NULL) {
            psi_free(*target);
            return -1;
        }
        *target = ptr;
        errno = 0;
        r = readlink(link, *target, size-1);
    }
    if (r == -1) {
        psi_free(*target);
        if (errno == EACCES)
            return -2;
        else if (errno == ENOENT) {
            PyErr_SetFromErrnoWithFilename(PyExc_ValueError, link);
            return -1;
        } else {
            PyErr_SetFromErrnoWithFilename(PyExc_SystemError, link);
            return -1;
        }
    }
    (*target)[r] = '\0';
    return 0;
}


int
psi_strings_count(const char *cmdl, const int size)
{
    int i = 0;
    int n = 0;

    assert(size > 0);

    while (i < size) {
        if (cmdl[i] == '\0')
            n += 1;
        i++;
    }
    return n;
}


char **
psi_strings_to_array(char *buf, const int count)
{
    char **array;
    char *ptr;
    int i;
    int j;
    int l;

    array = psi_malloc(count * sizeof(char*));
    if (array == NULL)
        return NULL;
    ptr = buf;
    for (i = 0; i < count; i++) {
        l = strlen(ptr) + 1;
        array[i] = psi_malloc(l);
        if (array[i] == NULL) {
            for (j = 0; j < i; j++)
                psi_free(array[j]);
            psi_free(array);
            return NULL;
        }
        memcpy(array[i], ptr, l);
        ptr += l;
    }
    return array;
}


/** Initialise datetime module
 *
 * This initialises the FROMTIMESTAMP and TIMEDELTA global variables.
 */
static int
init_datetime(void)
{
    PyObject *mod;
    PyObject *dt;

    mod = PyImport_ImportModule("datetime");
    if (mod == NULL)
        return -1;
    dt = PyObject_GetAttrString(mod, "datetime");
    if (dt == NULL) {
        Py_DECREF(mod);
        return -1;
    }
    FROMTIMESTAMP = PyObject_GetAttrString(dt, "utcfromtimestamp");
    Py_DECREF(dt);
    if (FROMTIMESTAMP == NULL) {
        Py_DECREF(mod);
        return -1;
    }
    TIMEDELTA = PyObject_GetAttrString(mod, "timedelta");
    Py_DECREF(mod);
    if (TIMEDELTA == NULL) {
        Py_CLEAR(FROMTIMESTAMP);
        return -1;
    }
    return 0;
}


/* Can't use PyDateTime_IMPORT and all API things associated with it since
 * that was only introduced in python 2.4 and we support 2.3 as a minimum.
 * Even if we could it would be pain to use for this. */
PyObject *
psi_timespec2datetime(struct timespec *tspec)
{
    PyObject *datetime;
    PyObject *timedelta;
    PyObject *ret;

    if (FROMTIMESTAMP == NULL || TIMEDELTA == NULL)
        if (init_datetime() < 0)
            return NULL;
    datetime = PyObject_CallFunction(FROMTIMESTAMP, "(l)", tspec->tv_sec);
    if (datetime == NULL)
        return NULL;
    timedelta = PyObject_CallFunction(TIMEDELTA, "(iil)",
                                      0, 0, tspec->tv_nsec/1000);
    if (timedelta == NULL) {
        Py_DECREF(datetime);
        return NULL;
    }
    ret = PyObject_CallMethod(datetime, "__add__", "(O)", timedelta);
    Py_DECREF(datetime);
    Py_DECREF(timedelta);
    return ret;
}


PyObject *
psi_timespec2timedelta(struct timespec *tspec)
{
    if (TIMEDELTA == NULL)
        if (init_datetime() < 0)
            return NULL;
    return PyObject_CallFunction(TIMEDELTA, "(ill)",
                                 0, tspec->tv_sec, tspec->tv_nsec/1000);
}


#if PY_VERSION_HEX <= 0x02040000 /* 2.4 */

/* This is copied from Python 2.6 sources. */

#include <locale.h>

/* ascii character tests (as opposed to locale tests) */
#define ISSPACE(c)  ((c) == ' ' || (c) == '\f' || (c) == '\n' || \
                     (c) == '\r' || (c) == '\t' || (c) == '\v')
#define ISDIGIT(c)  ((c) >= '0' && (c) <= '9')

/**
 * PyOS_ascii_strtod:
 * @nptr:    the string to convert to a numeric value.
 * @endptr:  if non-%NULL, it returns the character after
 *           the last character used in the conversion.
 *
 * Converts a string to a #gdouble value.
 * This function behaves like the standard strtod() function
 * does in the C locale. It does this without actually
 * changing the current locale, since that would not be
 * thread-safe.
 *
 * This function is typically used when reading configuration
 * files or other non-user input that should be locale independent.
 * To handle input from the user you should normally use the
 * locale-sensitive system strtod() function.
 *
 * If the correct value would cause overflow, plus or minus %HUGE_VAL
 * is returned (according to the sign of the value), and %ERANGE is
 * stored in %errno. If the correct value would cause underflow,
 * zero is returned and %ERANGE is stored in %errno.
 * If memory allocation fails, %ENOMEM is stored in %errno.
 *
 * This function resets %errno before calling strtod() so that
 * you can reliably detect overflow and underflow.
 *
 * Return value: the #gdouble value.
 **/
double
PyOS_ascii_strtod(const char *nptr, char **endptr)
{
    char *fail_pos;
    double val = -1.0;
    struct lconv *locale_data;
    const char *decimal_point;
    size_t decimal_point_len;
    const char *p, *decimal_point_pos;
    const char *end = NULL; /* Silence gcc */
    const char *digits_pos = NULL;
    int negate = 0;

    assert(nptr != NULL);

    fail_pos = NULL;

    locale_data = localeconv();
    decimal_point = locale_data->decimal_point;
    decimal_point_len = strlen(decimal_point);

    assert(decimal_point_len != 0);

    decimal_point_pos = NULL;

    /* We process any leading whitespace and the optional sign manually,
       then pass the remainder to the system strtod.  This ensures that
       the result of an underflow has the correct sign. (bug #1725)  */

    p = nptr;
    /* Skip leading space */
    while (ISSPACE(*p))
        p++;

    /* Process leading sign, if present */
    if (*p == '-') {
        negate = 1;
        p++;
    } else if (*p == '+') {
        p++;
    }

    /* What's left should begin with a digit, a decimal point, or one of
       the letters i, I, n, N. It should not begin with 0x or 0X */
    if ((!ISDIGIT(*p) &&
         *p != '.' && *p != 'i' && *p != 'I' && *p != 'n' && *p != 'N')
        ||
        (*p == '0' && (p[1] == 'x' || p[1] == 'X')))
    {
        if (endptr)
            *endptr = (char*)nptr;
        errno = EINVAL;
        return val;
    }
    digits_pos = p;

    if (decimal_point[0] != '.' ||
        decimal_point[1] != 0)
    {
        while (ISDIGIT(*p))
            p++;

        if (*p == '.')
        {
            decimal_point_pos = p++;

            while (ISDIGIT(*p))
                p++;

            if (*p == 'e' || *p == 'E')
                p++;
            if (*p == '+' || *p == '-')
                p++;
            while (ISDIGIT(*p))
                p++;
            end = p;
        }
        else if (strncmp(p, decimal_point, decimal_point_len) == 0)
        {
            /* Python bug #1417699 */
            if (endptr)
                *endptr = (char*)nptr;
            errno = EINVAL;
            return val;
        }
        /* For the other cases, we need not convert the decimal
           point */
    }

    /* Set errno to zero, so that we can distinguish zero results
       and underflows */
    errno = 0;

    if (decimal_point_pos)
    {
        char *copy, *c;

        /* We need to convert the '.' to the locale specific decimal
           point */
        copy = (char *)PyMem_MALLOC(end - digits_pos +
                                    1 + decimal_point_len);
        if (copy == NULL) {
            if (endptr)
                *endptr = (char *)nptr;
            errno = ENOMEM;
            return val;
        }

        c = copy;
        memcpy(c, digits_pos, decimal_point_pos - digits_pos);
        c += decimal_point_pos - digits_pos;
        memcpy(c, decimal_point, decimal_point_len);
        c += decimal_point_len;
        memcpy(c, decimal_point_pos + 1,
               end - (decimal_point_pos + 1));
        c += end - (decimal_point_pos + 1);
        *c = 0;

        val = strtod(copy, &fail_pos);

        if (fail_pos)
        {
            if (fail_pos > decimal_point_pos)
                fail_pos = (char *)digits_pos +
                    (fail_pos - copy) -
                    (decimal_point_len - 1);
            else
                fail_pos = (char *)digits_pos +
                    (fail_pos - copy);
        }

        PyMem_FREE(copy);

    }
    else {
        val = strtod(digits_pos, &fail_pos);
    }

    if (fail_pos == digits_pos)
        fail_pos = (char *)nptr;

    if (negate && fail_pos != nptr)
        val = -val;

    if (endptr)
        *endptr = fail_pos;

    return val;
}

double
PyOS_ascii_atof(const char *nptr)
{
	return PyOS_ascii_strtod(nptr, NULL);
}

#endif
