#Boa:Frame:MainPeElfFrame
#
#   Description:
#       PyPEELF Main Window
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

__revision__ = "$Id: pypeelf.py 170 2009-08-24 18:35:05Z reversing $"

import wx
import pefile
import sys
import os

import directory
import sections
import tasks
import about

from app.common import hex_up_8, hex_up_4
from app import compute_hash, signaturesdb, pedata

class FileDropTarget(wx.FileDropTarget):
    """This object implements Drop Target functionality for files"""
    def __init__(self, obj):
        """ Initialize the Drop Target, passing in the Frame reference"""
        # Initialize the wsFileDropTarget Object
        wx.FileDropTarget.__init__(self)
        # Store the Object Reference for dropped files
        self.frame = obj

    def OnDropFiles(self, x, y, filenames):
        """ Implement File Drop """
        if filenames:
            self.frame._load_file(filenames[0])
            
def create(parent):
    return MainPeElfFrame(parent)

[wxID_MAINPEELFFRAME, wxID_MAINPEELFFRAMEABOUT, 
 wxID_MAINPEELFFRAMEADDITIONALINFO, wxID_MAINPEELFFRAMEBASEOFCODE, 
 wxID_MAINPEELFFRAMEBASEOFDATA, wxID_MAINPEELFFRAMEBROWSE, 
 wxID_MAINPEELFFRAMECHARACTERISTICS, wxID_MAINPEELFFRAMEDIRECTORY, 
 wxID_MAINPEELFFRAMEENTRYPOINT, wxID_MAINPEELFFRAMEEXIT, 
 wxID_MAINPEELFFRAMEFALIGNMENT, wxID_MAINPEELFFRAMEFILEINFO, 
 wxID_MAINPEELFFRAMEFILEPATH, wxID_MAINPEELFFRAMEHASHES, 
 wxID_MAINPEELFFRAMEIMAGEBASE, wxID_MAINPEELFFRAMEMACHINETYPE, 
 wxID_MAINPEELFFRAMENUMBEROFSECTIONS, wxID_MAINPEELFFRAMENUMBEROFSYMBOLS, 
 wxID_MAINPEELFFRAMESECALIGNMENT, wxID_MAINPEELFFRAMESECTIONS, 
 wxID_MAINPEELFFRAMESIZEOFHEADERS, wxID_MAINPEELFFRAMESIZEOFIMAGE, 
 wxID_MAINPEELFFRAMESIZEOFOPTIONALHDR, wxID_MAINPEELFFRAMESTATICBOX1, 
 wxID_MAINPEELFFRAMESTATICBOX2, wxID_MAINPEELFFRAMESTATICBOX3, 
 wxID_MAINPEELFFRAMESTATICBOX4, wxID_MAINPEELFFRAMESTATICTEXT1, 
 wxID_MAINPEELFFRAMESTATICTEXT10, wxID_MAINPEELFFRAMESTATICTEXT11, 
 wxID_MAINPEELFFRAMESTATICTEXT12, wxID_MAINPEELFFRAMESTATICTEXT13, 
 wxID_MAINPEELFFRAMESTATICTEXT14, wxID_MAINPEELFFRAMESTATICTEXT15, 
 wxID_MAINPEELFFRAMESTATICTEXT16, wxID_MAINPEELFFRAMESTATICTEXT2, 
 wxID_MAINPEELFFRAMESTATICTEXT3, wxID_MAINPEELFFRAMESTATICTEXT4, 
 wxID_MAINPEELFFRAMESTATICTEXT5, wxID_MAINPEELFFRAMESTATICTEXT6, 
 wxID_MAINPEELFFRAMESTATICTEXT7, wxID_MAINPEELFFRAMESTATICTEXT8, 
 wxID_MAINPEELFFRAMESTATICTEXT9, wxID_MAINPEELFFRAMESUBSYSTEM, 
 wxID_MAINPEELFFRAMESYMBOLTABLE, wxID_MAINPEELFFRAMETASKLIST, 
 wxID_MAINPEELFFRAMETIMADATESTAMP, wxID_MAINPEELFFRAME_BREAK, 
 wxID_MAINPEELFFRAME_FLC, wxID_MAINPEELFFRAME_OPTIONS, 
 wxID_MAINPEELFFRAME_REBUILDER, wxID_MAINPEELFFRAME_SPLIT, 
] = [wx.NewId() for _init_ctrls in range(52)]

class MainPeElfFrame(wx.Frame):
    def _init_ctrls(self, prnt):
        wx.Frame.__init__(self, id=wxID_MAINPEELFFRAME, name='', parent=prnt,
              pos=wx.Point(618, 221), size=wx.Size(541, 498),
              style=wx.DEFAULT_FRAME_STYLE^wx.MAXIMIZE_BOX^wx.RESIZE_BORDER, title='[PyPEELF v1.0 - PE and PE+ Editor]')

        # we define some characteristics in the window
        self.Centre()
        self.SetClientSize(wx.Size(533, 464))

        self.Bind(wx.EVT_CLOSE, self.OnClose)
        
        # accelerators for shortcuts
        x = [(wx.ACCEL_NORMAL, wx.WXK_ESCAPE, wxID_MAINPEELFFRAME),]
        
        aTable = wx.AcceleratorTable(x)
        self.SetAcceleratorTable(aTable)
        
        self.FileInfo = wx.StaticBox(id=wxID_MAINPEELFFRAMEFILEINFO,
              label='File Info', name='FileInfo', parent=self, pos=wx.Point(8,
              40), size=wx.Size(200, 88), style=0)

        self.staticBox1 = wx.StaticBox(id=wxID_MAINPEELFFRAMESTATICBOX1,
              label='Optional Header', name='staticBox1', parent=self,
              pos=wx.Point(8, 136), size=wx.Size(200, 240), style=0)

        self.staticBox2 = wx.StaticBox(id=wxID_MAINPEELFFRAMESTATICBOX2,
              label='File Header', name='staticBox2', parent=self,
              pos=wx.Point(216, 40), size=wx.Size(208, 248), style=0)

        self.staticBox3 = wx.StaticBox(id=wxID_MAINPEELFFRAMESTATICBOX3,
              label='Tables', name='staticBox3', parent=self, pos=wx.Point(216,
              288), size=wx.Size(200, 88), style=0)

        self.staticBox4 = wx.StaticBox(id=wxID_MAINPEELFFRAMESTATICBOX4,
              label='Options', name='staticBox4', parent=self, pos=wx.Point(432,
              0), size=wx.Size(96, 376), style=0)

        self.filepath = wx.TextCtrl(id=wxID_MAINPEELFFRAMEFILEPATH,
              name='filepath', parent=self, pos=wx.Point(8, 8),
              size=wx.Size(416, 24), style=0, value='...')

        self.browse = wx.Button(id=wxID_MAINPEELFFRAMEBROWSE, label='Browse',
              name='browse', parent=self, pos=wx.Point(440, 24),
              size=wx.Size(75, 23), style=0)

        self.tasklist = wx.Button(id=wxID_MAINPEELFFRAMETASKLIST,
              label='Task list', name='tasklist', parent=self, pos=wx.Point(440,
              56), size=wx.Size(75, 23), style=0)

        self.about = wx.Button(id=wxID_MAINPEELFFRAMEABOUT, label='About',
              name='about', parent=self, pos=wx.Point(440, 304),
              size=wx.Size(75, 23), style=0)

        self.exit = wx.Button(id=wxID_MAINPEELFFRAMEEXIT, label='Exit',
              name='exit', parent=self, pos=wx.Point(440, 336), size=wx.Size(75,
              23), style=0)

        self.staticText1 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT1,
              label='Entry Point', name='staticText1', parent=self,
              pos=wx.Point(16, 64), size=wx.Size(54, 13), style=0)

        self.staticText2 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT2,
              label='Image Base', name='staticText2', parent=self,
              pos=wx.Point(16, 96), size=wx.Size(57, 13), style=0)

        self.entrypoint = wx.TextCtrl(id=wxID_MAINPEELFFRAMEENTRYPOINT,
              name='entrypoint', parent=self, pos=wx.Point(112, 64),
              size=wx.Size(88, 21), style=0, value='')

        self.imagebase = wx.TextCtrl(id=wxID_MAINPEELFFRAMEIMAGEBASE,
              name='imagebase', parent=self, pos=wx.Point(112, 96),
              size=wx.Size(88, 21), style=0, value='')

        self.staticText3 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT3,
              label='Base of Code', name='staticText3', parent=self,
              pos=wx.Point(16, 160), size=wx.Size(65, 13), style=0)

        self.staticText4 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT4,
              label='Base of Data', name='staticText4', parent=self,
              pos=wx.Point(16, 192), size=wx.Size(63, 13), style=0)

        self.staticText5 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT5,
              label='Size of Image', name='staticText5', parent=self,
              pos=wx.Point(16, 224), size=wx.Size(66, 13), style=0)

        self.staticText6 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT6,
              label='Size of Headers', name='staticText6', parent=self,
              pos=wx.Point(16, 256), size=wx.Size(76, 13), style=0)

        self.staticText7 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT7,
              label='Section Alignment', name='staticText7', parent=self,
              pos=wx.Point(16, 288), size=wx.Size(86, 13), style=0)

        self.staticText8 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT8,
              label='File Alignment', name='staticText8', parent=self,
              pos=wx.Point(16, 320), size=wx.Size(67, 13), style=0)

        self.staticText9 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT9,
              label='Subsystem', name='staticText9', parent=self,
              pos=wx.Point(16, 352), size=wx.Size(53, 13), style=0)

        self.baseofcode = wx.TextCtrl(id=wxID_MAINPEELFFRAMEBASEOFCODE,
              name='baseofcode', parent=self, pos=wx.Point(112, 152),
              size=wx.Size(88, 21), style=0, value='')

        self.baseofdata = wx.TextCtrl(id=wxID_MAINPEELFFRAMEBASEOFDATA,
              name='baseofdata', parent=self, pos=wx.Point(112, 184),
              size=wx.Size(88, 21), style=0, value='')

        self.sizeofimage = wx.TextCtrl(id=wxID_MAINPEELFFRAMESIZEOFIMAGE,
              name='sizeofimage', parent=self, pos=wx.Point(112, 216),
              size=wx.Size(88, 21), style=0, value='')

        self.sizeofheaders = wx.TextCtrl(id=wxID_MAINPEELFFRAMESIZEOFHEADERS,
              name='sizeofheaders', parent=self, pos=wx.Point(112, 248),
              size=wx.Size(88, 21), style=0, value='')

        self.secalignment = wx.TextCtrl(id=wxID_MAINPEELFFRAMESECALIGNMENT,
              name='secalignment', parent=self, pos=wx.Point(112, 280),
              size=wx.Size(88, 21), style=0, value='')

        self.falignment = wx.TextCtrl(id=wxID_MAINPEELFFRAMEFALIGNMENT,
              name='falignment', parent=self, pos=wx.Point(112, 312),
              size=wx.Size(88, 21), style=0, value='')

        self.subsystem = wx.TextCtrl(id=wxID_MAINPEELFFRAMESUBSYSTEM,
              name='subsystem', parent=self, pos=wx.Point(112, 344),
              size=wx.Size(88, 21), style=0, value='')

        self.staticText10 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT10,
              label='Machine Type', name='staticText10', parent=self,
              pos=wx.Point(232, 64), size=wx.Size(67, 13), style=0)

        self.staticText11 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT11,
              label='Number of Sections', name='staticText11', parent=self,
              pos=wx.Point(232, 96), size=wx.Size(94, 13), style=0)

        self.staticText12 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT12,
              label='Time Date Stamp', name='staticText12', parent=self,
              pos=wx.Point(232, 128), size=wx.Size(82, 13), style=0)

        self.staticText13 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT13,
              label='Ptr to Symbol Table', name='staticText13', parent=self,
              pos=wx.Point(232, 160), size=wx.Size(94, 13), style=0)

        self.staticText14 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT14,
              label='Number of Symbols', name='staticText14', parent=self,
              pos=wx.Point(232, 192), size=wx.Size(93, 13), style=0)

        self.staticText15 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT15,
              label='Size of Opt. Header', name='staticText15', parent=self,
              pos=wx.Point(232, 224), size=wx.Size(96, 13), style=0)

        self.staticText16 = wx.StaticText(id=wxID_MAINPEELFFRAMESTATICTEXT16,
              label='Characteristics', name='staticText16', parent=self,
              pos=wx.Point(232, 256), size=wx.Size(72, 13), style=0)

        self.machinetype = wx.TextCtrl(id=wxID_MAINPEELFFRAMEMACHINETYPE,
              name='machinetype', parent=self, pos=wx.Point(328, 64),
              size=wx.Size(88, 21), style=0, value='')

        self.numberofsections = wx.TextCtrl(id=wxID_MAINPEELFFRAMENUMBEROFSECTIONS,
              name='numberofsections', parent=self, pos=wx.Point(328, 96),
              size=wx.Size(88, 21), style=0, value='')

        self.timadatestamp = wx.TextCtrl(id=wxID_MAINPEELFFRAMETIMADATESTAMP,
              name='timadatestamp', parent=self, pos=wx.Point(328, 128),
              size=wx.Size(88, 21), style=0, value='')

        self.symboltable = wx.TextCtrl(id=wxID_MAINPEELFFRAMESYMBOLTABLE,
              name='symboltable', parent=self, pos=wx.Point(328, 160),
              size=wx.Size(88, 21), style=0, value='')

        self.numberofsymbols = wx.TextCtrl(id=wxID_MAINPEELFFRAMENUMBEROFSYMBOLS,
              name='numberofsymbols', parent=self, pos=wx.Point(328, 192),
              size=wx.Size(88, 21), style=0, value='')

        self.sizeofoptionalhdr = wx.TextCtrl(id=wxID_MAINPEELFFRAMESIZEOFOPTIONALHDR,
              name='sizeofoptionalhdr', parent=self, pos=wx.Point(328, 224),
              size=wx.Size(88, 21), style=0, value='')

        self.characteristics = wx.TextCtrl(id=wxID_MAINPEELFFRAMECHARACTERISTICS,
              name='characteristics', parent=self, pos=wx.Point(328, 256),
              size=wx.Size(88, 21), style=0, value='')

        self.sections = wx.Button(id=wxID_MAINPEELFFRAMESECTIONS,
              label='Sections', name='sections', parent=self, pos=wx.Point(224,
              328), size=wx.Size(75, 23), style=0)
        
        self.directory = wx.Button(id=wxID_MAINPEELFFRAMEDIRECTORY,
              label='Directory', name='directory', parent=self,
              pos=wx.Point(328, 328), size=wx.Size(75, 23), style=0)
        
        self.hashes = wx.ListBox(choices=[], id=wxID_MAINPEELFFRAMEHASHES,
              name='hashes', parent=self, pos=wx.Point(16, 400),
              size=wx.Size(504, 48), style=0)

        self.additionalinfo = wx.StaticBox(id=wxID_MAINPEELFFRAMEADDITIONALINFO,
              label='Additional File Information', name='additionalinfo',
              parent=self, pos=wx.Point(8, 384), size=wx.Size(520, 72),
              style=0)

        self._break = wx.Button(id=wxID_MAINPEELFFRAME_BREAK, label='Break',
              name='_break', parent=self, pos=wx.Point(440, 88),
              size=wx.Size(75, 23), style=0)

        self._rebuilder = wx.Button(id=wxID_MAINPEELFFRAME_REBUILDER,
              label='Rebuilder', name='_rebuilder', parent=self,
              pos=wx.Point(440, 120), size=wx.Size(75, 23), style=0)

        self._flc = wx.Button(id=wxID_MAINPEELFFRAME_FLC, label='FLC',
              name='_flc', parent=self, pos=wx.Point(440, 152), size=wx.Size(75,
              23), style=0)

        self._options = wx.Button(id=wxID_MAINPEELFFRAME_OPTIONS,
              label='Options', name='_options', parent=self, pos=wx.Point(440,
              216), size=wx.Size(75, 23), style=0)

        self._split = wx.Button(id=wxID_MAINPEELFFRAME_SPLIT, label='Split',
              name='_split', parent=self, pos=wx.Point(440, 184),
              size=wx.Size(75, 23), style=0)

        # we bind all the button to the function handler.
        self.Bind(wx.EVT_KEY_DOWN, self.OnKeyDown)
        self.browse.Bind(wx.EVT_BUTTON, self.OnBrowseButton, id=wxID_MAINPEELFFRAMEBROWSE)
        self.tasklist.Bind(wx.EVT_BUTTON, self.OnTasklistButton, id=wxID_MAINPEELFFRAMETASKLIST)
        self.about.Bind(wx.EVT_BUTTON, self.OnAboutButton, id=wxID_MAINPEELFFRAMEABOUT)
        self.exit.Bind(wx.EVT_BUTTON, self.OnExitButton, id=wxID_MAINPEELFFRAMEEXIT)
        self.sections.Bind(wx.EVT_BUTTON, self.OnSectionsButton, id=wxID_MAINPEELFFRAMESECTIONS)
        self.directory.Bind(wx.EVT_BUTTON, self.OnDirectoryButton, id=wxID_MAINPEELFFRAMEDIRECTORY)
        
        self.sections.Enable(False)
        self.directory.Enable(False)
        
    def __init__(self, parent):
        self._init_ctrls(parent)
        
        self.peInstance = parent.peInstance
        # Create a File Drop Target object
        fdt = FileDropTarget(self)
        # Link the Drop Target Object to the Text Control
        self.SetDropTarget(fdt)

        self.filename = None
        self.mainDlg = parent
        #self.peInstance = None
        self.__packer = False
        self.isIA64 = False
        self.isx86 = False
    
    def Restore(self):
        self.Show()
        self.SetFocus()
        
    def OnKeyDown(self, event):
        keycode = event.GetKeyCode()
        if keycode == wx.WXK_ESCAPE:
            ret  = wx.MessageBox('Are you sure to quit?', 'Leave PyPEELF?', wx.YES_NO | wx.NO_DEFAULT, self)
            if ret == wx.YES:
                self.Close()
            else:
                self.SetFocus()
        event.Skip()

    def OnExitButton(self, event):
        # just close the app.
        self.Close()

    #def SetFilePath(self, path):
    #    self.filepath = path
        
    def _load_file(self, filename):
        """Load the given file into PyPEELF"""
        self.filepath.SetValue(str(filename))
        ## we load the file using pefile from ero carrera!.
        #try:
        #    self.peInstance = pefile.PE(filename)
        #except pefile.PEFormatError, e:
        #    wx.MessageBox(e.value, "Pe Format Error", wx.ICON_ERROR)
        #    self.filepath.SetValue("...")
        #    return
        #
        line = "-" * 100
        self.hashes.Append("PyPEELF v1.0 - Multi-Platform Binary Editor")
        self.hashes.Append(line)
        self.hashes.Append("Gathering file information...")
        self.hashes.Append(line)
        if self.peInstance.PE_TYPE == 0x10b:
            self.hashes.Append("Microsoft PE-Executable - 32 bits (x86)")
            self.isx86 = True
        else:
            if self.peInstance.PE_TYPE == 0x20b:
                self.hashes.Append("Microsoft PE-Executable - 64 bits (IA64)")
                self.isIA64 = True

        self.printPeHeaderData(pedata.getPEHeaderData(self.peInstance))
        
        if self.__packer:
            self.hashes.Append("Compiler/Packer: %s" % signaturesdb.getSignature(self.peInstance))

        self.hashes.Append("Filename: %s" % os.path.basename(filename))
        self.hashes.Append("File Size: %d bytes" % os.stat(filename)[6])
        self.hashes.Append(line)
        try:
            fd = open(filename, "rb")
            fz = os.stat(filename)[6]
            self.hashes.Append("File Hashes")
            self.hashes.Append(line)
            # here, we calculate the file MD5, SHA-1, and CRC-32 hashes
            self.hashes.Append("CRC-32: %s" % hex(abs(compute_hash.computeCRC32Hash(fd, fz))).replace("0x", "").upper())
            self.hashes.Append("MD5: %s" % compute_hash.computeMd5Hash(fd).upper())
            self.hashes.Append("SHA-1: %s" % compute_hash.computeSha512Hash(fd).upper())
            fd.close()
        except IOError:
            wx.MessageBox("Error: Unable to open the file %s in read mode" % filename)

        self.sections.Enable(True)
        self.directory.Enable(True)


    def OnBrowseButton(self, event):
        # for now, we only accept .exe and .dll file types.
        filters = 'Executable Files (*.exe)|*.exe|Dinamyc Libraries (*dll)|*.dll|All files (*.*)|*.*'

        # open file dialog.
        dialog = wx.FileDialog ( None, message = 'Select file....', wildcard = filters, style = wx.OPEN | wx.MULTIPLE )

        # if the user click on OK...
        if dialog.ShowModal() == wx.ID_OK:
            # we get the file path and print it.
            file_path = dialog.GetPaths()[0]
            
            #self.filepath.SetValue(str(file_path))
            # we load the file using pefile from ero carrera!.
            try:
                self.peInstance = pefile.PE(file_path)
                self._load_file(file_path)
            except pefile.PEFormatError, e:
                wx.MessageBox(e.value, "Pe Format Error", wx.ICON_ERROR)
                self.filepath.SetValue("...")
                return

            #self._load_file(file_path)

    def printPeHeaderData(self, pdata):
        self.entrypoint.SetValue(hex_up_8(pdata["EntryPoint"]))
        self.imagebase.SetValue(hex_up_8(pdata["ImageBase"]))
        self.baseofcode.SetValue(hex_up_8(pdata["BaseOfCode"]))
        
        if not self.isIA64:
            self.baseofdata.SetValue(hex_up_8(pdata["BaseOfData"]))
            
        self.sizeofimage.SetValue(hex_up_8(pdata["SizeOfImage"]))
        self.sizeofheaders.SetValue(hex_up_8(pdata["SizeOfHeaders"]))
        self.secalignment.SetValue(hex_up_8(pdata["SectionAlignment"]))
        self.falignment.SetValue(hex_up_8(pdata["FileAlignment"]))
        self.subsystem.SetValue(hex_up_4(pdata["Subsystem"]))
        self.machinetype.SetValue(hex_up_4(pdata["MachineType"]))
        self.numberofsections.SetValue(hex_up_4(pdata["NumberOfSections"]))
        self.timadatestamp.SetValue(hex_up_8(pdata["TimeDateStamp"]))
        self.symboltable.SetValue(hex_up_8(pdata["PointerToSymbolTable"]))
        self.numberofsymbols.SetValue(hex_up_8(pdata["NumberOfSymbols"]))
        self.sizeofoptionalhdr.SetValue(hex_up_4(pdata["SizeOfOptionalHeader"]))
        self.characteristics.SetValue(hex_up_4(pdata["Characteristics"]))
    
    def OnDirectoryButton(self, event):
        tablesDialog = directory.create(self)
        tablesDialog.Show()
        self.Hide()

    def OnSectionsButton(self, event):
        sectionsDialog = sections.create(self)        
        sectionsDialog.Show()
        self.Hide()
        
    def OnTasklistButton(self, event):
        tasksDialog = tasks.create(self)
        tasksDialog.Show()

    def OnAboutButton(self, event):
        about.About(self)
    
    def OnClose(self, event):
        self.mainDlg.Show()
        self.Destroy()
        
if __name__ == '__main__':
    app = wx.PySimpleApp()
    frame = create(None)
    frame.Show()
    frame.SetFocus()
    
    app.MainLoop()
    
