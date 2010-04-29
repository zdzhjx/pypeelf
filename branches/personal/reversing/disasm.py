import struct
import pefile
import pydasm
import sys

MAX_OPCODE = 0x10

def main():
    print '[+] python disasm.py path_to_executable'
    
    if len(sys.argv) > 1:
        path    = sys.argv[1]
        
        file = openFile             (path)
        basicPeInfo                 (file)
##        disasmEp                    (file)
##        listImports                 (file)
##        listSections                (file)
##        listModules                 (file)
##        listImportedFunctionsInfo   (file)
    else:
        raise 'path_to_executable not specified'
    
def basicPeInfo(file):
    print '-' * 40
    print '[+] Optional Header'
    print '-' * 40
    print 'EntryPoint:           0x%08x' % file.OPTIONAL_HEADER.AddressOfEntryPoint
    print 'ImageBase:            0x%08x' % file.OPTIONAL_HEADER.ImageBase
    print 'BaseOfCode:           0x%08x' % file.OPTIONAL_HEADER.BaseOfCode
    print 'BaseOfData:           0x%08x' % file.OPTIONAL_HEADER.BaseOfData
    print 'SizeOfImage:          0x%08x' % file.OPTIONAL_HEADER.SizeOfImage
    print 'SizeOfHeaders:        0x%08x' % file.OPTIONAL_HEADER.SizeOfHeaders
    print 'SectionAligment:      0x%08x' % file.OPTIONAL_HEADER.SectionAlignment
    print 'FileAligment:         0x%08x' % file.OPTIONAL_HEADER.FileAlignment
    print 'Subsystem:            0x%08x' % file.OPTIONAL_HEADER.Subsystem
    print '-' * 40
    print '[+] File Header'
    print '-' * 40
    print 'MachineType:          0x%08x' % file.FILE_HEADER.Machine
    print 'NumberOfSections:     0x%08x' % file.FILE_HEADER.NumberOfSections
    print 'TimeDateStamp:        0x%08x' % file.FILE_HEADER.TimeDateStamp
    print 'PointerToSymbolTable: 0x%08x' % file.FILE_HEADER.PointerToSymbolTable
    print 'NumberOfSymbols:      0x%08x' % file.FILE_HEADER.NumberOfSymbols
    print 'SizeOfOptionalHeader: 0x%08x' % file.FILE_HEADER.SizeOfOptionalHeader
    print 'Characteristics:      0x%08x' % file.FILE_HEADER.Characteristics
    
def openFile(path):
    return pefile.PE(path)

def procOp(bytes_hexa):
    if len(bytes_hexa) < MAX_OPCODE:
        bytes_hexa += ' ' * (MAX_OPCODE - len(bytes_hexa))
    return bytes_hexa

def disasmEp(file):
    ep      = file.OPTIONAL_HEADER.AddressOfEntryPoint
    ib      = file.OPTIONAL_HEADER.ImageBase
    data    = file.get_memory_mapped_image()[ep:ep+100]
    offset  = 0

    while offset < len(data)-1:
        i           = pydasm.get_instruction(data[offset:],pydasm.MODE_32)
        bytes       = data[offset:offset+i.length]
        bytes_hexa  = ''.join(['%02x' % ord (b) for b in bytes])
        
        print '%x %s %s' % (ep+ib+offset,procOp(bytes_hexa),pydasm.get_instruction_string(i,pydasm.FORMAT_INTEL,ep+offset+ib))
        offset      += i.length
        
def listModules(file):
    print '-' * 100
    print 'DllName\t OriginalFirstThunk\t TimeDateStamp\t ForwarderChain\t Name\t FirstThunk'
    print '-' * 100
    
    for i in file.DIRECTORY_ENTRY_IMPORT:
        print '%s\t 0x%08x\t 0x%08x\t 0x%08x\t 0x%08x\t 0x%08x\t' % (\
            i.dll, i.struct.OriginalFirstThunk,\
            i.struct.TimeDateStamp,\
            i.struct.ForwarderChain,\
            i.struct.Name,\
            i.struct.FirstThunk)
        
def listImports(file):
    for i in file.DIRECTORY_ENTRY_IMPORT:
        print '\n[+] %s' % i.dll
        for j in i.imports:
            print j.name
            
def listImportedFunctionsInfo(file):
    print '-' * 100
    print 'Address\t RVA\t Offset\t Hint\t FunctionName'
    print '-' * 100
    for dll in file.DIRECTORY_ENTRY_IMPORT:
        # print dll.dll
        for imp in dll.imports:
            print '%08x %08x %08x %04x %s' %(\
              imp.address, imp.hint_name_table_rva,\
              imp.hint_name_table_rva - file.sections[0].VirtualAddress + file.sections[0].PointerToRawData,\
              imp.hint, repr(imp.name))
    
def listSections(file):
    print '-' * 100
    print 'Section\t VirtualSize\t VirtualOffset\t RawSize\t RawOffset\t Characteristics'
    print '-' * 100
    
    for i in file.sections:
        section = i.Name
        section_name = section[:section.find('\x00')]
        print '%s\t 0x%08x\t 0x%08x\t 0x%08x\t 0x%08x\t 0x%08x' % (\
            section_name,\
            i.Misc_VirtualSize,\
            i.VirtualAddress,\
            i.SizeOfRawData,\
            i.PointerToRawData,\
            i.Characteristics)
        
if __name__ == '__main__':
    main()
    