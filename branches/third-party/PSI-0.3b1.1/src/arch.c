/* The MIT License
 *
 * Copyright (C) 2007 Chris Miles
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

/** psi.arch.Arch* classes
 *
 * This file contains the common support for the psi.arch.Arch classes and
 * factory functions.
 */


#include <Python.h>

#include <errno.h>
#include <stdlib.h>

#include "psi.h"
#include "arch.h"


#define RELEASE_INFO_SIZE 5


/* The Python ArchBase object */
typedef struct {
    PyObject_HEAD
    struct psi_archinfo *archi;
    int release_info[RELEASE_INFO_SIZE]; /* release_info tuple */
    int release_info_size;               /* number of entries in release_info */
} ArchBaseObject;


/* Helper functions */


void *
psi_free_archinfo(struct psi_archinfo *archi)
{
    psi_FREE(archi->sysname);
    psi_FREE(archi->release);
    psi_FREE(archi->version);
    psi_FREE(archi->machine);
    psi_FREE(archi->nodename);
    psi_free(archi);
    return NULL;
}


/** Parse a relase string into a release_info tuple
 *
 * This function will try to parse the release string into an array of
 * integers.  Roughly equivalent to this python code: [int(i) for i in
 * release.split('-')[0].split('.')]
 *
 * @param release_info: The array to store the result into.
 * @param size: The size of the array.
 * @param release: The release string.
 *
 * @returns The number of items set in `release_info', -1 on failure.
 */
static int
set_release_info(int *release_info, const int size, const char *release)
{
    char *reldup;
    char *relpart;
    char *p;
    int i = 0;

    reldup = psi_strdup(release);
    relpart = reldup;
    if (relpart == NULL) {
        psi_free(reldup);
        return -1;
    }
    p = strchr(relpart, '-');
    if (p != NULL)
        *p = '\0';
    p = strchr(relpart, '.');
    while (p != NULL) {
        *p++ = '\0';
        errno = 0;
        release_info[i] = (int)strtol(relpart, (char**)NULL, 10);
        if (errno != 0) {
            PyErr_Format(PyExc_ValueError,
                         "Failed to parse release string '%s' into a tuple: %s",
                         release, strerror(errno));
            psi_free(reldup);
            return -1;
        }
        relpart = p;
        p = strchr(relpart, '.');
        i++;
        if (i == size) {
            PyErr_Format(PyExc_OverflowError,
                         "More then %d parts in release string '%s'",
                         size, release);
            psi_free(reldup);
            return -1;
        }
    }
    errno = 0;
    release_info[i] = (int)strtol(relpart, (char**)NULL, 10);
    psi_free(reldup);
    if (errno != 0) {
        PyErr_Format(PyExc_ValueError,
                     "Failed to parse '%s' into a tuple: %s",
                     release, strerror(errno));
        return -1;
    }
    return i + 1;
}


/* ArchBase methods */


static int
ArchBase_init(ArchBaseObject *self, PyObject *args, PyObject *kwds)
{
    if (args != NULL && PySequence_Length(args) > 0) {
        PyErr_Format(PyExc_TypeError,
                     "__init__() takes no arguments (%d given)",
                     (int)PySequence_Length(args));
        return -1;
    }
    if (kwds != NULL && PyMapping_Length(kwds) > 0) {
        PyErr_SetString(PyExc_TypeError,
                        "__init__() takes no keyword arguments");
        return -1;
    }
    self->archi = psi_arch_archinfo();
    if (self->archi == NULL)
        return -1;
    if (self->archi->release_status == PSI_STATUS_OK) {
        self->release_info_size = set_release_info(self->release_info,
                                                   RELEASE_INFO_SIZE,
                                                   self->archi->release);
        if (self->release_info_size < 0) {
            psi_free_archinfo(self->archi);
            return -1;
        }
    }
    return 0;
}


static void
ArchBase_dealloc(ArchBaseObject *self)
{
    if (self->archi != NULL)
        psi_free_archinfo(self->archi);
    Py_TYPE(self)->tp_free((PyObject*)self);
}


static PyObject *
ArchBase_repr(ArchBaseObject *self)
{
    return PyStr_FromFormat("%s()", Py_TYPE(self)->tp_name);
}


static PyObject *
ArchBase_get_sysname(ArchBaseObject *self, void *closure)
{
    if (self->archi == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Instance has not been initialised properly");
        return NULL;
    }
    if (psi_checkattr("Arch.sysname", self->archi->sysname_status) == -1)
        return NULL;
    return PyStr_FromString(self->archi->sysname);
}


static PyObject *
ArchBase_get_release(ArchBaseObject *self, void *closure)
{
    if (self->archi == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Instance has not been initialised properly");
        return NULL;
    }
    if (psi_checkattr("Arch.release", self->archi->release_status) == -1)
        return NULL;
    return PyStr_FromString(self->archi->release);
}


static PyObject *
ArchBase_get_release_info(ArchBaseObject *self, void *closure)
{
    PyObject *tuple;
    PyObject *item;
    Py_ssize_t i = (Py_ssize_t)self->release_info_size;
    Py_ssize_t j;

    if (self->archi == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Instance has not been initialised properly");
        return NULL;
    }
    if (psi_checkattr("Arch.release_info", self->archi->release_status) < 0)
        return NULL;
    tuple = PyTuple_New(i);
    if (tuple == NULL)
        return NULL;
    for (j = 0; j < i; j++) {
        item = PyLong_FromLong((long)self->release_info[j]);
        if (item == NULL) {
            Py_DECREF(tuple);
            return NULL;
        }
        PyTuple_SET_ITEM(tuple, j, item);
    }
    return tuple;
}


static PyObject *
ArchBase_get_version(ArchBaseObject *self, void *closure)
{
    if (self->archi == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Instance has not been initialised properly");
        return NULL;
    }
    if (psi_checkattr("Arch.version", self->archi->version_status) == -1)
        return NULL;
    return PyStr_FromString(self->archi->version);
}


static PyObject *
ArchBase_get_machine(ArchBaseObject *self, void *closure)
{
    if (self->archi == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Instance has not been initialised properly");
        return NULL;
    }
    if (psi_checkattr("Arch.machine", self->archi->machine_status) == -1)
        return NULL;
    return PyStr_FromString(self->archi->machine);
}


static PyObject *
ArchBase_get_nodename(ArchBaseObject *self, void *closure)
{
    if (self->archi == NULL) {
        PyErr_SetString(PyExc_RuntimeError,
                        "Instance has not been initialised properly");
        return NULL;
    }
    if (psi_checkattr("Arch.nodename", self->archi->nodename_status) == -1)
        return NULL;
    return PyStr_FromString(self->archi->nodename);
}


static PyGetSetDef ArchBase_getseters[] = {
    {"sysname", (getter)ArchBase_get_sysname, (setter)NULL,
     "Name of the operating system implementation", NULL},
    {"release", (getter)ArchBase_get_release, (setter)NULL,
     "Release level of the operating system", NULL},
    {"release_info", (getter)ArchBase_get_release_info, (setter)NULL,
     "Tuple representation of the operating system release level", NULL},
    {"version", (getter)ArchBase_get_version, (setter)NULL,
     "Version level of the operating system", NULL},
    {"machine", (getter)ArchBase_get_machine, (setter)NULL,
     "Machine hardware platform", NULL},
    {"nodename", (getter)ArchBase_get_nodename, (setter)NULL,
     "Network name of the machine", NULL},
    {NULL}                      /* Sentinel */
};


PyTypeObject ArchBase_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "psi.arch.ArchBase",                      /* tp_name */
    sizeof(ArchBaseObject),                   /* tp_basicsize */
    0,                                        /* tp_itemsize */
    /* methods */
    (destructor)ArchBase_dealloc,             /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    (reprfunc)ArchBase_repr,                  /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "Base object for all arch classes",       /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    ArchBase_getseters,                       /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)ArchBase_init,                  /* tp_init */
    0,                                        /* tp_alloc */
    PyType_GenericNew,                        /* tp_new */
};


PyTypeObject ArchDarwin_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "psi.arch.ArchDarwin",                    /* tp_name */
    sizeof(ArchBaseObject),                   /* tp_basicsize */
    0,                                        /* tp_itemsize */
    /* methods */
    0,                                        /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "This object represents a Darwin system", /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    &ArchBase_Type,                           /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};


PyTypeObject ArchSunOS_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "psi.arch.ArchSunOS",                     /* tp_name */
    sizeof(ArchBaseObject),                   /* tp_basicsize */
    0,                                        /* tp_itemsize */
    /* methods */
    0,                                        /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "This object represnets a SunOS system",  /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    &ArchBase_Type,                           /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};


PyTypeObject ArchLinux_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "psi.arch.ArchLinux",                     /* tp_name */
    sizeof(ArchBaseObject),                   /* tp_basicsize */
    0,                                        /* tp_itemsize */
    /* methods */
    0,                                        /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "This object represents a Linux system",  /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    &ArchBase_Type,                           /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};


PyTypeObject ArchAIX_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "psi.arch.ArchAIX",                       /* tp_name */
    sizeof(ArchBaseObject),                   /* tp_basicsize */
    0,                                        /* tp_itemsize */
    /* methods */
    0,                                        /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "This object represents an AIX system",   /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    0,                                        /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    &ArchBase_Type,                           /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    0,                                        /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};


/* Object Creation Functions */


PyObject *
newArchBaseObject(void)
{
    PyObject *obj;

    obj = PyType_GenericNew(&ArchBase_Type, NULL, NULL);
    if (obj == NULL)
        return NULL;
    if (ArchBase_init((ArchBaseObject *)obj, NULL, NULL) != 0) {
        Py_DECREF(obj);
        return NULL;
    }
    return obj;
}


PyObject *
newArchObject(void)
{
    PyObject *obj;

#ifdef DARWIN
    obj = PyType_GenericNew(&ArchDarwin_Type, NULL, NULL);
#elif SUNOS
    obj = PyType_GenericNew(&ArchSunOS_Type, NULL, NULL);
#elif LINUX
    obj = PyType_GenericNew(&ArchLinux_Type, NULL, NULL);
#elif AIX
    obj = PyType_GenericNew(&ArchAIX_Type, NULL, NULL);
#else
#   error "Unknown system, can't compile"
#endif
    if (obj == NULL)
        return NULL;
    if (ArchBase_init((ArchBaseObject *)obj, NULL, NULL) != 0) {
        Py_DECREF(obj);
        return NULL;
    }
    return obj;
}
