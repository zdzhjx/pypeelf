**PyPEELF is a multi-format and cross-platform binary editor** written in pure [Python](http://www.python.org/) language. Its GUI is [http://www.wxpython.org/ wxPython](.md)based code and a part of it was designed with [BOA Constructor](http://boa-constructor.sourceforge.net/).

With PyPEELF you can easily edit PE32, PE64 and ELF32 binary files. You can edit almost every field in the given structure. PyPEELF use [pefile](http://code.google.com/p/pefile/) from [Ero Carrera](http://dkbza.org/) to handle PE32 and PE64 binary files and [construct](http://construct.wikispaces.com/) to handle ELF32 binary files.

Also, PyPEELF has some extra modules like a Task Viewer written using [winappdbg](http://winappdbg.sourceforge.net/) and its own .NET API to handle .NET binary files.

PyPEELF is distributed under [MIT](http://en.wikipedia.org/wiki/MIT_License) license.

**Importan note: PyPEELF is still under development.**