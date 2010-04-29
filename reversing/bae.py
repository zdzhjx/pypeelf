#!/usr/bin/env python
#
#   Description:
#       Break and Enter module. This module allow to set an int3 in the EP
#       of the loaded program and if you have a JIT debugger on you will catch
#       the exception produced by the int3.
#   Author:
#       +NCR/CRC! [ReVeRsEr] (nriva)
#
# Copyright (c) 2009 Nahuel Cayetano Riva <nahuelriva@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

__revision__ = "$Id: bae.py 243 2009-09-28 21:14:41Z reversing $"

import wx
import pefile
import ctypes
import win32con

from ctypes import windll as dll

from winappdbg import win32

def BreakAtEP():
    debug = True
    isASLRPresent = False
    
    filters = 'Executable Files (*.exe)|*.exe|Dinamyc Libraries (*dll)|*.dll|All files (*.*)|*.*'
    
    dialog = wx.FileDialog ( None, message = 'Select file....', wildcard = filters, style = wx.OPEN | wx.MULTIPLE )
    
    if dialog.ShowModal() == wx.ID_OK:
        fp = str(dialog.GetPaths()[0])

        if debug:
            print "%s" % fp

        try:
            pe = pefile.PE(fp)
            if pe.OPTIONAL_HEADER.DllCharacteristics & 0x00FF == 0x40:
                # http://www.nynaeve.net/?p=100
                isASLRPresent = True
        except pefile.PEFormatError, e:
            raise str(e)

        b = ctypes.create_string_buffer(255)
        dll.kernel32.GetCurrentDirectoryA(255, b)
        CurrentDirectory = b.value

        if debug:
            print "CurDir: %s" % CurrentDirectory
        
        hProcess = win32.CreateProcess(fp,\
                                       win32con.NULL, \
                                       win32con.NULL, \
                                       win32con.NULL, \
                                       0, \
                                       win32con.CREATE_SUSPENDED, \
                                       win32con.NULL, \
                                       CurrentDirectory)

        _hProcess = hProcess.hProcess.value
        _hThread = hProcess.hThread.value
        
        if debug:
            print "hProcess: 0x%04x" % _hProcess
            print "hThread: 0x%04x" % _hProcess
        
        b = ctypes.create_string_buffer(255)


        if debug:
            print "EntryPoint: 0x%08x" % pe.OPTIONAL_HEADER.AddressOfEntryPoint
            print "ImageBase: 0x%08x" % pe.OPTIONAL_HEADER.ImageBase

        if isASLRPresent:
            print "ASLR!"
        else:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
        
        try:
            success = win32.WriteProcessMemory(_hProcess, ep, "\xcc")
            if not success:
                raise "Could not write to the specified address"
        except ctypes.WinError:
            raise "Could not write to the specified address"
        
        success = win32.ResumeThread(_hThread)
        
        if success == -1:
            raise "Could't resume thread."
        
        win32.CloseHandle(_hProcess)
        win32.CloseHandle(_hThread)
