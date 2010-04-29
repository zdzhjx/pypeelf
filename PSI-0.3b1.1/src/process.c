/* The MIT License
 *
 * Copyright (C) 2007 Chris Miles
 *
 * Copyright (C) 2008-2009 Floris Bruynooghe
 *
 * Copyright (C) 2008-2009 Abilisoft Ltd.
 *
 * Copyright (C) 2009 Erick Tryzelaar
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

/** psi.process.Process class
 *
 * This file contains the common support for the psi.process.Process class.
 */


#include <Python.h>

#include <string.h>
#include <time.h>

#include "psi.h"
#include "process.h"


/** The Python Process object
 *
 * `pid' and `proci' are filled in by the init method.  All the python objects
 * are filled lazily when they are accessed.  They exist so that accessing
 * them twice returns a new reference to the same objects instead of creating
 * new objects.  Just like in the psi_process structure some of these pointers
 * might never be used on some platforms, e.g. zoneid is Solaris-only.
 */
typedef struct {
    PyObject_HEAD
    pid_t pid;
    struct psi_process *proci;
    PyObject *pypid;
    PyObject *exe;
    PyObject *accounting_name;
    PyObject *args;
    PyObject *argc;
    PyObject *command;
    PyObject *env;
    PyObject *cwd;
    PyObject *euid;
    PyObject *egid;
    PyObject *ruid;
    PyObject *rgid;
    PyObject *zoneid;
    PyObject *zonename;
    PyObject *ppid;
    PyObject *pgrp;
    PyObject *sid;
    PyObject *priority;
    PyObject *nice;
    PyObject *start_time;
    PyObject *jiffies;
    PyObject *status;
    PyObject *nthreads;
    PyObject *terminal;
    PyObject *utime;
    PyObject *stime;
    PyObject *cputime;
    PyObject *rss;
    PyObject *vsz;
    PyObject *pcpu;
} ProcessObject;


/***** Local declarations *****/

static int check_init(ProcessObject *obj);


/***** Local functions *****/

void *
psi_free_process(struct psi_process *proci)
{
    int i;

    psi_FREE(proci->exe);
    psi_FREE(proci->accounting_name);
    if (proci->argv != NULL)
        for (i = 0; i < proci->argc; i++)
            psi_free(proci->argv[i]);
    psi_FREE(proci->argv);
    psi_FREE(proci->command);
    for (i = 0; i < proci->envc; i++)
        psi_free(proci->envv[i]);
    psi_FREE(proci->envv);
    psi_FREE(proci->cwd);
    psi_FREE(proci->terminal);
    psi_FREE(proci->zonename);
    psi_free(proci);
    return NULL;
}


static int
Process_init(ProcessObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"pid", NULL};
    pid_t pid;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &pid))
        return -1;
    self->pid = pid;
    self->proci = psi_arch_process(pid);
    if (self->proci == NULL)
        return -1;
    return 0;
}


static void
Process_dealloc(ProcessObject *self)
{
    if (self == NULL)
        return;
    if (self->proci != NULL)
        psi_free_process(self->proci);
    Py_XDECREF(self->pypid);
    Py_XDECREF(self->exe);
    Py_XDECREF(self->accounting_name);
    Py_XDECREF(self->args);
    Py_XDECREF(self->argc);
    Py_XDECREF(self->command);
    Py_XDECREF(self->env);
    Py_XDECREF(self->cwd);
    Py_XDECREF(self->euid);
    Py_XDECREF(self->egid);
    Py_XDECREF(self->ruid);
    Py_XDECREF(self->rgid);
    Py_XDECREF(self->ppid);
    Py_XDECREF(self->pgrp);
    Py_XDECREF(self->sid);
    Py_XDECREF(self->priority);
    Py_XDECREF(self->nice);
    Py_XDECREF(self->start_time);
    Py_XDECREF(self->jiffies);
    Py_XDECREF(self->status);
    Py_XDECREF(self->nthreads);
    Py_XDECREF(self->terminal);
    Py_XDECREF(self->utime);
    Py_XDECREF(self->stime);
    Py_XDECREF(self->cputime);
    Py_XDECREF(self->rss);
    Py_XDECREF(self->vsz);
    Py_XDECREF(self->pcpu);
    Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject *
Process_repr(ProcessObject *self)
{
    return PyStr_FromFormat("%s(pid=%d)",
                            Py_TYPE(self)->tp_name, (int)self->pid);
}


static long
Process_hash(ProcessObject *self)
{
    PyObject *tuple;
    long hash;

    if (self->pypid == NULL)
        self->pypid = PyLong_FromLong(self->pid);
    if (self->pypid == NULL)
        return -1;
#ifdef LINUX
    if (self->jiffies == NULL) {
        if (check_init(self) == -1)
            return -1;
        if (psi_checkattr("Process.jiffies", self->proci->jiffies_status) == -1)
            return -1;
        self->jiffies = PyLong_FromLong(self->proci->jiffies);
    }
    if (self->jiffies == NULL)
        return -1;
#else
    if (self->start_time == NULL) {
        if (check_init(self) == -1)
            return -1;
        if (psi_checkattr("Process.start_time", self->proci->start_time_status) == -1)
            return -1;
        self->start_time = psi_timespec2datetime(&self->proci->start_time);
    }
    if (self->start_time == NULL)
        return -1;
#endif

    if ((tuple = PyTuple_New(2)) == NULL)
        return -1;

    Py_INCREF(self->pypid);
    PyTuple_SET_ITEM(tuple, 0, self->pypid);
#ifdef LINUX
    Py_INCREF(self->jiffies);
    PyTuple_SET_ITEM(tuple, 1, self->jiffies);
#else
    Py_INCREF(self->start_time);
    PyTuple_SET_ITEM(tuple, 1, self->start_time);
#endif

    hash = PyObject_Hash(tuple);
    Py_DECREF(tuple);

    return hash;
}


static PyObject *
Process_richcompare(PyObject *v, PyObject *w, int op)
{
    ProcessObject *vo, *wo;
    PyObject *result;
    int istrue;

    if (!PyObject_TypeCheck(v, &Process_Type)
        || !PyObject_TypeCheck(w, &Process_Type)) {
        Py_INCREF(Py_NotImplemented);
        return Py_NotImplemented;
    }
    vo = (ProcessObject *)v;
    wo = (ProcessObject *)w;
    switch (op) {
        case Py_EQ:
            istrue = vo->pid == wo->pid;
            break;
        case Py_NE:
            istrue = vo->pid != wo->pid;
            break;
        case Py_LE:
            istrue = vo->pid <= wo->pid;
            break;
        case Py_GE:
            istrue = vo->pid >= wo->pid;
            break;
        case Py_LT:
            istrue = vo->pid < wo->pid;
            break;
        case Py_GT:
            istrue = vo->pid > wo->pid;
            break;
        default:
            assert(!"op unknown");
            istrue = 0;         /* To shut up compiler */
    }
    result = istrue ? Py_True : Py_False;
    Py_INCREF(result);
    return result;
}


/** Check if object is initialised
 *
 * Small helper function that checks if an object is properly initialised.
 *
 * XXX: Maybe this should go into util.c in some from.
 */
static int
check_init(ProcessObject *obj)
{
    if (obj->proci == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Instance has not been initialised properly");
        return -1;
    }
    return 0;
}


static PyObject *
Process_get_pid(ProcessObject *self, void *closure)
{
    if (self->pypid == NULL)
        self->pypid = PyLong_FromLong(self->pid);
    Py_XINCREF(self->pypid);
    return self->pypid;
}


static PyObject *
Process_get_exe(ProcessObject *self, void *closure)
{
    if (self->exe == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.exe", self->proci->exe_status) == -1)
            return NULL;
        self->exe = PyStr_FromString(self->proci->exe);
    }
    Py_XINCREF(self->exe);
    return self->exe;
}


#ifdef LINUX
static PyObject *
Process_get_accounting_name(ProcessObject *self, void *closure)
{
    if (self->accounting_name == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.accounting_name",
                          self->proci->accounting_name_status) == -1)
            return NULL;
        self->accounting_name = PyStr_FromString(self->proci->accounting_name);
    }
    Py_XINCREF(self->accounting_name);
    return self->accounting_name;
}
#endif


/** Create a tuple from the argv vector in the psi_process structure
 *
 * Each element in argv is allowed to be NULL in which case a None object
 * should be added to the tuple.
 */
static PyObject *
Process_get_args(ProcessObject *self, void *closure)
{
    PyObject *args;
    PyObject *arg;
    int i;

    if (self->args == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.args", self->proci->argc_status) == -1
            || psi_checkattr("Process.args", self->proci->argv_status) == -1)
            return NULL;
        args = PyTuple_New((Py_ssize_t)self->proci->argc);
        if (args == NULL)
            return NULL;
        for (i = 0; i < self->proci->argc; i++) {
            if (self->proci->argv[i] == NULL) {
                Py_INCREF(Py_None);
                arg = Py_None;
            } else {
                arg = PyStr_FromString(self->proci->argv[i]);
                if (arg == NULL) {
                    Py_DECREF(args);
                    return NULL;
                }
            }
            PyTuple_SET_ITEM(args, i, arg);
        }
        self->args = args;
    }
    Py_INCREF(self->args);
    return self->args;
}


static PyObject *
Process_get_argc(ProcessObject *self, void *closure)
{
    if (self->argc == NULL) {
        if (check_init(self) < -1)
            return NULL;
        if (psi_checkattr("Process.argc", self->proci->argc_status) < 0)
            return NULL;
        self->argc = PyLong_FromLong(self->proci->argc);
    }
    Py_XINCREF(self->argc);
    return self->argc;
}


static PyObject *
Process_get_command(ProcessObject *self, void *closure)
{
    if (self->command == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.command", self->proci->command_status) == -1)
            return NULL;
        self->command = PyStr_FromString(self->proci->command);
    }
    Py_XINCREF(self->command);
    return self->command;
}


static PyObject *
Process_get_env(ProcessObject *self, void *closure)
{
    PyObject *env;
    PyObject *val;
    char *key;
    char *s;
    char *equals;
    int i;
    int r;

    if (self->env == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.env", self->proci->envc_status) == -1
            || psi_checkattr("Process.env", self->proci->envv_status) == -1)
            return NULL;
        env = PyDict_New();
        if (env == NULL)
            return NULL;
        s = (char *) self->proci->envv;
        for (i = 0; i < self->proci->envc; i++) {
            key = self->proci->envv[i];
            equals = strchr(key, '=');
            if (!equals)
                /* This is possible on at least Linux */
                continue;
            *equals = '\0';
            val = PyStr_FromString(equals + 1);
            if (val == NULL) {
                Py_DECREF(env);
                return NULL;
            }
            r = PyDict_SetItemString(env, key, val);
            Py_DECREF(val);
            if (r == -1)
                return NULL;
        }
        self->env = env;
    }
    Py_INCREF(self->env);
    return self->env;
}


#if ! (defined(SUNOS5) && SUNOS5_MINOR < 10)
static PyObject *
Process_get_cwd(ProcessObject *self, void *closure)
{
    if (self->cwd == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.cwd", self->proci->cwd_status))
            return NULL;
        self->cwd = PyStr_FromString(self->proci->cwd);
    }

    Py_XINCREF(self->cwd);
    return self->cwd;
}
#endif


static PyObject *
Process_get_euid(ProcessObject *self, void *closure)
{
    if (self->euid == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.uid", self->proci->euid_status) == -1)
            return NULL;
        self->euid = PyLong_FromLong(self->proci->euid);
    }
    Py_XINCREF(self->euid);
    return self->euid;
}


static PyObject *
Process_get_egid(ProcessObject *self, void *closure)
{
    if (self->egid == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.gid", self->proci->egid_status) == -1)
            return NULL;
        self->egid = PyLong_FromLong(self->proci->egid);
    }
    Py_XINCREF(self->egid);
    return self->egid;
}


static PyObject *
Process_get_ruid(ProcessObject *self, void *closure)
{
    if (self->ruid == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.real_uid", self->proci->ruid_status) == -1)
            return NULL;
        self->ruid = PyLong_FromLong(self->proci->ruid);
    }
    Py_XINCREF(self->ruid);
    return self->ruid;
}


static PyObject *
Process_get_rgid(ProcessObject *self, void *closure)
{
    if (self->rgid == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.real_gid", self->proci->rgid_status) == -1)
            return NULL;
        self->rgid = PyLong_FromLong(self->proci->rgid);
    }
    Py_XINCREF(self->rgid);
    return self->rgid;
}


#if defined(SUNOS5) && SUNOS5_MINOR >= 10
static PyObject *
Process_get_zoneid(ProcessObject *self, void *closure)
{
    if (self->zoneid == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.zoneid", self->proci->zoneid_status) == -1)
            return NULL;
        self->zoneid = PyLong_FromLong(self->proci->zoneid);
    }
    Py_XINCREF(self->zoneid);
    return self->zoneid;
}
#endif


#if defined(SUNOS5) && SUNOS5_MINOR >= 10
static PyObject *
Process_get_zonename(ProcessObject *self, void *closure)
{
    if (self->zonename == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.zonename",
                          self->proci->zonename_status) == -1)
            return NULL;
        self->zonename = PyStr_FromString(self->proci->zonename);
    }
    Py_XINCREF(self->zonename);
    return self->zonename;
}
#endif


static PyObject *
Process_get_ppid(ProcessObject *self, void *closure)
{
    if (self->ppid == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.ppid", self->proci->ppid_status) == -1)
            return NULL;
        self->ppid = PyLong_FromLong((long)self->proci->ppid);
    }
    Py_XINCREF(self->ppid);
    return self->ppid;
}


static PyObject *
Process_get_sid(ProcessObject *self, void *closure)
{
    if (self->sid == NULL) {
        if (check_init(self) < -1)
            return NULL;
        if (psi_checkattr("Process.sid", self->proci->sid_status) < 0)
            return NULL;
        self->sid = PyLong_FromLong(self->proci->sid);
    }
    Py_XINCREF(self->sid);
    return self->sid;
}


static PyObject *
Process_get_pgrp(ProcessObject *self, void *closure)
{
    if (self->pgrp == NULL) {
        if (check_init(self) < -1)
            return NULL;
        if (psi_checkattr("Process.pgrp", self->proci->pgrp_status) < 0)
            return NULL;
        self->pgrp = PyLong_FromLong(self->proci->pgrp);
    }
    Py_XINCREF(self->pgrp);
    return self->pgrp;
}


static PyObject *
Process_get_priority(ProcessObject *self, void *closure)
{
    if (self->priority == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.priority",
                          self->proci->priority_status) == -1)
            return NULL;
        self->priority = PyLong_FromLong((long)self->proci->priority);
    }
    Py_XINCREF(self->priority);
    return self->priority;
}


static PyObject *
Process_get_nice(ProcessObject *self, void *closure)
{
    if (self->nice == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.nice", self->proci->nice_status) == -1)
            return NULL;
        self->nice = PyLong_FromLong((long)self->proci->nice);
    }
    Py_XINCREF(self->nice);
    return self->nice;
}


static PyObject *
Process_get_start_time(ProcessObject *self, void *closure)
{
    if (self->start_time == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.start_time", self->proci->start_time_status)
            == -1)
            return NULL;
        self->start_time = psi_timespec2datetime(&self->proci->start_time);
    }
    Py_XINCREF(self->start_time);
    return self->start_time;
}


static PyObject *
Process_get_status(ProcessObject *self, void *closure)
{
    if (self->status == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.status", self->proci->status_status) == -1)
            return NULL;
        self->status = PyLong_FromLong((long)self->proci->status);
    }
    Py_XINCREF(self->status);
    return self->status;
}


#ifndef LINUX2_4
static PyObject *
Process_get_nthreads(ProcessObject *self, void *closure)
{
    if (self->nthreads == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.nthreads",
                          self->proci->nthreads_status) == -1)
            return NULL;
        self->nthreads = PyLong_FromLong((long)self->proci->nthreads);
    }
    Py_XINCREF(self->nthreads);
    return self->nthreads;
}
#endif


#if ! (defined(SUNOS5) && SUNOS5_MINOR < 10)
static PyObject *
Process_get_terminal(ProcessObject *self, void *closure)
{
    if (self->terminal == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.terminal",
                          self->proci->terminal_status) == -1)
            return NULL;
        if (self->proci->terminal == '\0') {
            Py_INCREF(Py_None);
            self->terminal = Py_None;
        } else
            self->terminal = PyStr_FromString(self->proci->terminal);
    }
    Py_XINCREF(self->terminal);
    return self->terminal;
}
#endif


static PyObject *
Process_get_utime(ProcessObject *self, void *closure)
{
    if (self->utime == NULL) {
        if (check_init(self) < 0)
            return NULL;
        if (psi_checkattr("Process.utime", self->proci->utime_status) < 0)
            return NULL;
        self->utime = psi_timespec2timedelta(&self->proci->utime);
    }
    Py_XINCREF(self->utime);
    return self->utime;
}


static PyObject *
Process_get_stime(ProcessObject *self, void *closure)
{
    if (self->stime == NULL) {
        if (check_init(self) < 0)
            return NULL;
        if (psi_checkattr("Process.stime", self->proci->stime_status) < 0)
            return NULL;
        self->stime = psi_timespec2timedelta(&self->proci->stime);
    }
    Py_XINCREF(self->stime);
    return self->stime;
}


static PyObject *
Process_get_cputime(ProcessObject *self, void *closure)
{
    if (self->cputime == NULL) {
        if (check_init(self) < 0)
            return NULL;
        if (psi_checkattr("Process.cputime", self->proci->cputime_status) < 0)
            return NULL;
        self->cputime = psi_timespec2timedelta(&self->proci->cputime);
    }
    Py_XINCREF(self->cputime);
    return self->cputime;
}


static PyObject *
Process_get_rss(ProcessObject *self, void *closure)
{
    if (self->rss == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.rss", self->proci->rss_status) == -1)
            return NULL;
        self->rss = PyLong_FromLong(self->proci->rss);
    }
    Py_XINCREF(self->rss);
    return self->rss;
}


static PyObject *
Process_get_vsz(ProcessObject *self, void *closure)
{
    if (self->vsz == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.vsz", self->proci->vsz_status) == -1)
            return NULL;
        self->vsz = PyLong_FromLong(self->proci->vsz);
    }
    Py_XINCREF(self->vsz);
    return self->vsz;
}


#if !defined(LINUX) && !defined(AIX)
static PyObject *
Process_get_pcpu(ProcessObject *self, void *closure)
{
    if (self->pcpu == NULL) {
        if (check_init(self) == -1)
            return NULL;
        if (psi_checkattr("Process.pcpu", self->proci->pcpu_status) == -1)
            return NULL;
        self->pcpu = PyFloat_FromDouble(self->proci->pcpu);
    }
    Py_XINCREF(self->pcpu);
    return self->pcpu;
}
#endif


static PyGetSetDef Process_getseters[] = {
    {"pid", (getter)Process_get_pid, (setter)NULL,
     "Process PID", NULL},
    {"exe", (getter)Process_get_exe, (setter)NULL,
     "Absolute pathname to the executable of the process", NULL},
#ifdef LINUX
    {"accounting_name", (getter)Process_get_accounting_name, (setter)NULL,
     "Accounting name of the process", NULL},
#endif
    {"args", (getter)Process_get_args, (setter)NULL,
     "List of the command and it's arguments\n"
     "\n"
     "On some systems (e.g. SunOS, AIX) it possible that this is not\n"
     "available due to privileges.  The `command' attribute should still\n"
     "be available in those cases.", NULL},
    {"argc", (getter)Process_get_argc, (setter)NULL,
     "Argument count", NULL},
    {"command", (getter)Process_get_command, (setter)NULL,
     "Command and arguments as a string\n"
     "\n"
     "On some systems (e.g. SunOS, AIX) this might be truncated to a limited\n"
     "length.  On those systems this will always be available however, while\n"
     "the `args' attribute might not be.", NULL},
    {"env", (getter)Process_get_env, (setter)NULL,
     "The environment of the process as a dictionary", NULL},
#if ! (defined(SUNOS5) && SUNOS5_MINOR < 10)
    {"cwd", (getter)Process_get_cwd, (setter)NULL,
     "Current working directory", NULL},
#endif
    {"euid", (getter)Process_get_euid, (setter)NULL,
     "Current UID", NULL},
    {"egid", (getter)Process_get_egid, (setter)NULL,
     "Current GID", NULL},
    {"ruid", (getter)Process_get_ruid, (setter)NULL,
     "Real UID", NULL},
    {"rgid", (getter)Process_get_rgid, (setter)NULL,
     "Real GID", NULL},
#if defined(SUNOS5) && SUNOS5_MINOR >= 10
    {"zoneid", (getter)Process_get_zoneid, (setter)NULL,
     "ID of the Solaris zone the process is running in", NULL},
    {"zonename", (getter)Process_get_zonename, (setter)NULL,
     "Name of the Solaris zone the process is running in", NULL},
#endif
    {"ppid", (getter)Process_get_ppid, (setter)NULL,
     "Parent PID", NULL},
    {"pgrp", (getter)Process_get_pgrp, (setter)NULL,
     "Process group ID aka PID of process group leader", NULL},
    {"sid", (getter)Process_get_sid, (setter)NULL,
     "Session ID of the process", NULL},
    {"priority", (getter)Process_get_priority, (setter)NULL,
     "Priority of the process", NULL},
    {"nice", (getter)Process_get_nice, (setter)NULL,
     "Nice value of the process", NULL},
    {"start_time", (getter)Process_get_start_time, (setter)NULL,
     "Start time of process as datetime.datetime object\n\n"
     "Use .strftime('%s') to get seconds since epoch",
     NULL},
    {"status", (getter)Process_get_status, (setter)NULL,
     "Process status\n\n"
     "A value matching one of the psi.process.PROC_STATUS_* constants", NULL},
#ifndef LINUX2_4
    {"nthreads", (getter)Process_get_nthreads, (setter)NULL,
     "Number of threads used by this process", NULL},
#endif
#if ! (defined(SUNOS5) && SUNOS5_MINOR < 10)
    {"terminal", (getter)Process_get_terminal, (setter)NULL,
     "Owning terminal or None", NULL},
#endif
    {"utime", (getter)Process_get_utime, (setter)NULL,
     "Time the process has spent in user mode (datetime.timedelta)", NULL},
    {"stime", (getter)Process_get_stime, (setter)NULL,
     "Time the process has spend in system mode (datetime.timedelta)", NULL},
    {"cputime", (getter)Process_get_cputime, (setter)NULL,
     "Total CPU time of the process (datetime.timedelta)", NULL},
    {"rss", (getter)Process_get_rss, (setter)NULL,
     "Resident memory size (RSS) in bytes", NULL},
    {"vsz", (getter)Process_get_vsz, (setter)NULL,
     "Virtual memory size in bytes", NULL},
#if !defined(LINUX) && !defined(AIX)
    {"pcpu", (getter)Process_get_pcpu, (setter)NULL,
     "%% CPU usage, instantaneous", NULL},
#endif
    {NULL}  /* Sentinel */
};


PyTypeObject Process_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "psi.process.Process",                    /* tp_name */
    sizeof(ProcessObject),                    /* tp_basicsize */
    0,                                        /* tp_itemsize */
    /* methods */
    (destructor)Process_dealloc,              /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    (reprfunc)Process_repr,                   /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    (hashfunc)Process_hash,                   /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Process(pid=x) -> Process object",       /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    (richcmpfunc)Process_richcompare,         /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    Process_getseters,                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)Process_init,                   /* tp_init */
    0,                                        /* tp_alloc */
    PyType_GenericNew,                        /* tp_new */
};


/** Create a new ProcessObject
 *
 * This calls PyType_GenericNew() and Process_init() for you with correct
 * error handling.  See Process_init() for arguments accepted.
 *
 * @param args: positional arguments
 * @param kwargs: keyword arguments
 *
 * @returns New reference to a ProcessObject or NULL in case of an error.
 */
PyObject *
newProcessObject(PyObject *args, PyObject *kwargs)
{
    PyObject *obj;

    obj = PyType_GenericNew(&Process_Type, args, kwargs);
    if (obj == NULL)
        return NULL;
    if (Process_init((ProcessObject *)obj, args, kwargs) == -1) {
        Py_DECREF(obj);
        return NULL;
    }
    return obj;
}
