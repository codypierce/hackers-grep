#
# diSlib64 - diStorm PE library
# Gil Dabah, 2007
# http://ragestorm.net/distorm/
#
# Thanks to Roee Shenberg for the OO.
# Thanks to TFKyle for the Impors/Exports/Relocs property idea (loaded upon demand).
# Thanks to Fred Male for the minor Exports bug fix.
#
#Copyright (c) 2007, Gil Dabah
#All rights reserved.
#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#    * Neither the name of the diStorm nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import os
import sys
import struct
import cStringIO

def ReadAsciiz(buf):
    try:
        return buf[:buf.index('\x00')]
    except ValueError:
        return None

MZ_HEADER_LENGTH = 0x40
PE_HEADER_LENGTH = 0x18
PE_HEADER_OFFSET = 0x3c
OPTHDR_SIZE_OFFSET = 0x14
SECTION_SIZE = 0x28

IMAGE_FILE_MACHINE_I386 = 0x14c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

MAGIC_PE32 = 0x10b
MAGIC_PE32_PLUS = 0x20b

class PEException(Exception):
    pass

def SafeRead(f, length):
    """Tries to read and will raise an exception if there are not enough bytes."""
    data = f.read(length)
    if len(data) != length:
        raise IOError("Couldn't read enough bytes!")
    return data

def GetQword(s, offset, count = 1):
    if count == 1:
        return struct.unpack("<Q", s[offset:offset + 8])[0]
    else:
        return struct.unpack("<%dQ" % count ,s[offset:offset + 8*count])

def GetDword(s, offset, count = 1):
    if count == 1:
        return struct.unpack("<L", s[offset:offset + 4])[0]
    else:
        return struct.unpack("<%dL" % count ,s[offset:offset + 4*count])

def GetShort(s, offset, count = 1):
    if count == 1:
        return struct.unpack("<H", s[offset:offset + 2])[0]
    else:
        return struct.unpack("<%dH" % count, s[offset:offset + 2*count])

class _MZHeader(object):
    """MZ File Header object. Intended for internal use only."""
    def __init__(self,f):
        try:
            f.seek(0)
            MZHeader = f.read(MZ_HEADER_LENGTH)
            if len(MZHeader) < MZ_HEADER_LENGTH:
                raise PEException("Cannot read MZ header.")
        except IOError:
            raise PEException("Cannot read MZ header.")

        if (MZHeader[:2] != "MZ"):
            raise PEException("Invalid MZ file.")

        self.PEHeaderOffset = GetDword(MZHeader, PE_HEADER_OFFSET)

class PEFile(object):
    def __init__(self, FileName, NewImageBase = None):
        """Filename can be either a file object or filename."""
        ImportsOff = 0
        ExportsOff = 0
        RelocationsOff = 0
        RelocationsSize = 0
        self._Imports = None
        self._Exports = None
        self._Relocs = None
        # Holds the delta between the original ImageBase and the new one.
        self.Delta = 0
        if isinstance(FileName, basestring):
            try:
                f = open(FileName, "rb")
            except IOError:
                raise PEException("File not found or cannot be accessed.")
        elif isinstance(FileName, file):
            f = FileName
        else:
            raise PEException("Invalid file/filename argument!")

        self._MZHeader = _MZHeader(f)
        # People might want to check this one out.
        self.PEHeaderOffset = self._MZHeader.PEHeaderOffset

        f.seek(self.PEHeaderOffset)
        try:
            PEHeader = SafeRead(f, PE_HEADER_LENGTH)
        except IOError:
            raise PEException("Cannot read PE header.")

        if (PEHeader[:4] != "PE\0\0"):
            raise PEException("Invalid PE file.")

        self.MachineType = GetShort(PEHeader, 4)
        if self.MachineType != IMAGE_FILE_MACHINE_I386 and self.MachineType != IMAGE_FILE_MACHINE_AMD64:
            raise PEException("PE file is not an i386+ image.")

        OptHeaderSize = GetShort(PEHeader, OPTHDR_SIZE_OFFSET)
        try:
            #OptHeader = SafeRead(f, OptHeaderSize)
            OptHeader = f.read(0xf8)
        except IOError:
            raise PEException("Cannot read optional PE header.")

        self.OptMagic = GetShort(OptHeader, 0)
        if self.OptMagic != MAGIC_PE32 and self.OptMagic != MAGIC_PE32_PLUS:
            raise PEException("Optional header magic isn't not a PE32+.")

        CodeSize = GetDword(OptHeader, 4)

        EntryPoint, CodeBase = GetDword(OptHeader, 0x10, 2)
        if (self.OptMagic == MAGIC_PE32):
            DataBase, ImageBase = GetDword(OptHeader, 0x18, 2)
        else:
            DataBase = 0 # No DataBase for AMD64
            ImageBase = GetQword(OptHeader, 0x18)

        SectionAlignment, FileAlignment = GetDword(OptHeader, 0x20, 2)
        SectionAlignment -= 1
        FileAlignment -= 1

        # Delta holds the difference between the original image base and the given one,
        # this will be used in order to apply the relocations correctly.
        if (NewImageBase != None):
            self.Delta = NewImageBase - ImageBase
            ImageBase = NewImageBase

        NumOfSections = GetShort(PEHeader, 6)
        try:
            f.seek(self.PEHeaderOffset + OptHeaderSize + 0x18)
            RawSections = SafeRead(f, NumOfSections * SECTION_SIZE)
        except IOError:
            raise PEException("Cannot read in sections.")

        DirectoriesOffset = 0x60
        if (self.OptMagic == MAGIC_PE32_PLUS):
            DirectoriesOffset += 0x10
        NumberOfRvaAndSizes = GetDword(OptHeader, DirectoriesOffset-4)
        if 0 < NumberOfRvaAndSizes:
            try:
                ExportsOff = GetDword(OptHeader, DirectoriesOffset)
            except:
                pass
        if 1 < NumberOfRvaAndSizes:
            try:
                ImportsOff = GetDword(OptHeader, DirectoriesOffset + 8)
            except:
                pass
        if 5 < NumberOfRvaAndSizes:
            try:
                RelocationsOff = GetDword(OptHeader, DirectoriesOffset + 0x28)
                RelocationsSize = GetDword(OptHeader, DirectoriesOffset + 0x2c)
            except:
                pass

        try:
            self.SizeOfHeaders = GetDword(OptHeader, 0x3c)
        except:
            raise PEException("Cannot read SizeOfHeaders")
        try:
            self.SizeOfImage = GetDword(OptHeader, 0x38)
        except:
            raise PEException("Cannot read SizeOfImage")

        f.seek(0)
        FileMap = f.read()
        f.close()
        Sections = []

        for i in xrange(0, NumOfSections*SECTION_SIZE, SECTION_SIZE):
            SecName = RawSections[i:i + 8].strip('\x00')
            SecVA, SecSize, SecFileOffset = GetDword(RawSections, i + 0xc, 3)
            SecFlags = GetDword(RawSections, i + 0x24)
            # Align everything.
            SecVA &= ~SectionAlignment
            if (SecVA < self.SizeOfHeaders):
                SecVA = 0
            SecFileOffset &= ~(FileAlignment)
            SecSize = (SecSize + FileAlignment) & ~FileAlignment
            try:
                SecBin = FileMap[SecFileOffset:SecFileOffset + SecSize]
                # Align the section to SectionAlignment and pad section with zeros.
                alignSize = SectionAlignment + 1 - (len(SecBin) % (SectionAlignment+1))
                if (alignSize != SectionAlignment + 1):
                    SecBin += '\x00' * alignSize
            except:
                raise PEException("Cannot read section or size invalid.")
            Sections.append(Section(i / SECTION_SIZE, SecName, SecVA, SecFlags, SecBin))

        # Create a section for the whole file, in case there are VA's which point to no section.
        # Make sure it's the last section so GetSectionByVA scans it lastly.
        # Also align this section to SectionAlignment.
        Sections.append(Section(-1, "FILEMAP", 0, 0, FileMap + '\x00' * (SectionAlignment + 1 - (len(FileMap) % (SectionAlignment+1)))))

        self.Sections = Sections
        self.CodeSize = CodeSize
        self.EntryPoint = EntryPoint
        self.CodeBase = CodeBase
        self.DataBase = DataBase
        self.ImageBase = ImageBase
        self.RelocationsSize = RelocationsSize
        self.RelocationsOff = RelocationsOff
        self.ImportsOff = ImportsOff
        self.ExportsOff = ExportsOff

    def _GetImports(self):
        """ Getter for self.Imports. """
        if self._Imports != None or not self.ImportsOff:
            return self._Imports
        # Loads and caches imports upon first request.
        self._Imports = self.LoadImports()
        return self._Imports

    def _GetExports(self):
        """ Getter for self.Exports. """
        if self._Exports != None or not self.ExportsOff:
            return  self._Exports
        # Loads and caches exports upon first request.
        self._Exports = self.LoadExports()
        return self._Exports

    def _GetRelocs(self):
        """ Getter for self.Relocs. """
        if self._Relocs != None or not self.RelocationsOff:
            return self._Relocs
        # Loads and caches relocations and apply them upon first request.
        self._Relocs = self.GetRelocations()
        self.ApplyRelocations()
        return self._Relocs

    # Use properties for Imports/Exports/Relocs, so they will be loaded only once upon demand.
    Imports = property(_GetImports)
    Exports = property(_GetExports)
    Relocs = property(_GetRelocs)

    def GetSectionByVA(self, VA):
        for i in self.Sections:
            if (VA >= i.VA) and (VA < (i.VA + i.Size)):
                return i
        return None

    def LoadImports(self):
        ImpSec = self.GetSectionByVA(self.ImportsOff)
        VA = self.ImportsOff
        ImageBase = self.ImageBase
        if (ImpSec == None):
            raise PEException("Cannot find import table section.")
        Imports = [] 
        VA -= ImpSec.VA
        while True:
            try:
                ModuleNameVA = GetDword(ImpSec.Data, VA + 0xc)
            except IndexError:
                raise PEException("Cannot read imported module name RVA.")
            try:
                FirstThunkVA = GetDword(ImpSec.Data, VA + 0x10)
            except IndexError:
                raise PEException("Cannot read imported functions addresses RVA.")
            # Stop parsing import descriptors on any of the next cases.
            if ModuleNameVA == 0 or FirstThunkVA == 0:
                break
            sec = self.GetSectionByVA(ModuleNameVA)
            if (sec == None):
                raise PEException("Cannot find imported module name.")

            ModuleName = ReadAsciiz(sec.Data[ModuleNameVA - sec.VA:])
            if (ModuleName == None):
                raise PEException("Cannot read imported module name.")
            FunctionsNamesAddrs = []
            try:
                OrigFirstThunkVA = GetDword(ImpSec.Data, VA)
            except IndexError:
                raise PEException("Cannot read imported functions names RVA.")
            PtrsSec = self.GetSectionByVA(FirstThunkVA)
            if (PtrsSec == None):
                raise PEException("Cannot find imported functions addresses.")

            # See if we can use Original Thunk or the First Thunk.
            if ((OrigFirstThunkVA == 0) or (OrigFirstThunkVA < self.SizeOfHeaders) or (OrigFirstThunkVA >= self.SizeOfImage)):
                # Continue anyways, some linkers use a zero OrigFirstThunkVA...
                # Prefer using First Thunk.
                OrigFirstThunkVA = FirstThunkVA

            sec = self.GetSectionByVA(OrigFirstThunkVA)
            if (sec == None):
                raise PEException("Cannot find imported functions names.")

            OrigFirstThunkVA -= sec.VA
            # Scan for the imported functions.
            while True:
                # Get an RVA to its ImportByName structure.
                try:
                    if (self.OptMagic == MAGIC_PE32):
                        ImportByNameVA = GetDword(sec.Data, OrigFirstThunkVA)
                        OrdBit = 1L << 31
                    else:
                        ImportByNameVA = GetQword(sec.Data, OrigFirstThunkVA)
                        OrdBit = 1L << 63
                except IndexError:
                    raise PEException("Cannot read ImportByName RVA.")
                # Is it the end of list?
                if (ImportByNameVA == 0):
                    break
                # Is this offset is actually an ordinal number?
                if (ImportByNameVA & OrdBit):
                    FuncName = "Ord_0x%04X" % (ImportByNameVA & 0xffff)
                else:
                    # Move next.
                    ImportByNameVA += 2
                    sec2 = self.GetSectionByVA(ImportByNameVA)
                    if (sec2 == None):
                        raise PEException("Cannot find imported function name section.")

                    ImportByNameVA -= sec2.VA
                    # Get the imported function name.
                    FuncName = ReadAsciiz(sec2.Data[ImportByNameVA:])
                    if (FuncName == None):
                        raise PEException("Cannot read imported function name.")

                    if (len(FuncName) == 0):
                        break
                # Address of pointer to function in the IAT.
                FunctionsNamesAddrs.append((FirstThunkVA + ImageBase, FuncName))
                if (self.OptMagic == MAGIC_PE32):
                    OrigFirstThunkVA += 4
                    FirstThunkVA += 4
                else:
                    OrigFirstThunkVA += 8
                    FirstThunkVA += 8
            # Create them all as Import class. Add the module and its functions to the list.
            Imports += [Import(va, fname, ModuleName) for va, fname in FunctionsNamesAddrs]
            # Next module.
            VA += 0x14
        return Imports

    def LoadExports(self):
        ExpSec = self.GetSectionByVA(self.ExportsOff)
        VA = self.ExportsOff
        CodeBase = self.CodeBase
        ImageBase = self.ImageBase
        if (ExpSec == None):
            raise PEException("Cannot find export table section.")

        if (len(ExpSec.Data) < 0x28):
            raise PEException("Export table too small!")

        VA -= ExpSec.VA
        # Read basic information about the Export Table.
        OrdinalBase, FuncsCount, NamesCount, FuncsAddrsVA = GetDword(ExpSec.Data, VA + 0x10, 4)

        # Get the functions' addresses array page.
        FuncsSec = self.GetSectionByVA(FuncsAddrsVA)
        if (FuncsSec == None):
            raise PEException("Cannot find export table functions addresses.")

        FuncsAddrsVA -= FuncsSec.VA
        
        NamesAddrsVA = GetDword(ExpSec.Data, VA + 0x20)
        NamesSec = self.GetSectionByVA(NamesAddrsVA)
        if (NamesSec == None):
            raise PEException("Cannot find export table functions names.")

        NamesAddrsVA -= NamesSec.VA

        # Get the functions' ordinals array page.
        OrdsAddrsVA = GetDword(ExpSec.Data, VA + 0x24)
        OrdsSec = self.GetSectionByVA(OrdsAddrsVA)
        if (OrdsSec == None):
            raise PEException("Cannot find export table functions ordinals.")

        OrdsAddrsVA -= OrdsSec.VA

        ordnum = 0
        FuncNames = []
        Names = []
        Ords = []
        # [addr, isUsed]
        if ((FuncsAddrsVA + FuncsCount*4) > len(FuncsSec.Data)):
            raise PEException("Exported functions count exceeds sections.")

        # Read in all addresses.
        if (FuncsCount == 1):
            Addrs = [[GetDword(FuncsSec.Data, FuncsAddrsVA, 1), 0]]
        else:
            Addrs = [[i, 0] for i in GetDword(FuncsSec.Data, FuncsAddrsVA, FuncsCount)]

        if ((NamesAddrsVA + NamesCount*4) > len(NamesSec.Data)):
            raise PEException("Exported functions count exceeds sections.")

        # Read in these functions' names.
        for i in xrange(NamesCount):
            NameVA = GetDword(NamesSec.Data, NamesAddrsVA + i*4)
            NameSec = self.GetSectionByVA(NameVA)
            if (NameSec == None):
                raise PEException("Cannot find exported function name.")

            NameVA -= NameSec.VA
            Name = ReadAsciiz(NameSec.Data[NameVA:])
            if (Name == None):
                raise PEException("Cannot read exported function name.")

            Names.append(Name)

        if ((OrdsAddrsVA + NamesCount*2) > len(OrdsSec.Data)):
            raise PEException("Exported functions count exceeds sections.")

        # Read the ordinals of these functions.
        if (NamesCount == 1):
            Ords = [GetShort(OrdsSec.Data, OrdsAddrsVA, 1)]
        else:
            Ords = GetShort(OrdsSec.Data, OrdsAddrsVA, NamesCount)

        # [name, ord]
        # Mark the functions which have a name and an ordinal.
        for i in enumerate(Names):
            j = Ords[i[0]]
            FuncNames.append(Export(i[1], j + OrdinalBase, Addrs[j][0]))
            # Mark exported function address as used.
            Addrs[j][1] = 1

        # Add functions that exported by ordinals only by exclusion.
        # This is a bit tricky, that's why we had a flag indicating whether the function was already ready to go...
        for i in [i for i in enumerate(Addrs) if i[1][1] != 1]:
            try:
                j = i[0] + OrdinalBase
                FuncNames.append(Export("", j, Addrs[j][0]))
            except:
                # i dont care about unnamed exports
                pass
        return FuncNames

    def GetRelocations(self):
        VA = self.RelocationsOff
        Size = self.RelocationsSize
        Sections = self.Sections
        # Read a page header.
        RelocatedAddrs = []
        RelocSec = self.GetSectionByVA(VA)
        if (RelocSec == None):
            raise PEException("Cannot find base relocations section.")

        VA -= RelocSec.VA
        Index = 0
        while VA < Size:
            if (VA + 8 > Size):
                raise PEException("Not enough bytes to read relocations header.")
            # Read a page header.
            PageVA, RelocCount = GetDword(RelocSec.Data, VA, 2)
            Index += 1
            # Calc the number of relocations in this page.
            RelocCount -= 8 #exclude header
            if (VA + RelocCount > Size):
                raise PEException("Relocations count exceeds section.")

            VA += 8
            # Read in the addresses.
            for i in xrange(RelocCount/2):
                # Is it the end of array? Halt.
                if (VA >= Size):
                    break
                TypeOffset = GetShort(RelocSec.Data, VA)
                # Is it the end of array? Halt.
                if (TypeOffset == 0):
                    # Skip ABSOLUTE relocation type, move to next page.
                    VA += RelocCount-i*2
                    break
                VA += 2
                # Extract the type and offset from the word sized variable.
                Type = TypeOffset >> 12
                Offset = TypeOffset & 0xfff
                # Executables of PE type support only HIGHLOW type.
                if (Type == 3):
                    PageSec = self.GetSectionByVA(PageVA + Offset)
                    if (PageSec != None):
                        # Append the data into the list as a Relocation class with the original relocated dword as well.
                        RelocatedAddrs.append(Relocation(PageSec, PageVA, Offset, GetDword(PageSec.Data, PageVA + Offset - PageSec.VA)))
                elif (Type == 10):
                    PageSec = self.GetSectionByVA(PageVA + Offset)
                    if (PageSec != None):
                        # Append the data into the list as a Relocation class with the original relocated qword as well.
                        RelocatedAddrs.append(Relocation(PageSec, PageVA, Offset, GetQword(PageSec.Data, PageVA + Offset - PageSec.VA)))

        return RelocatedAddrs

    def ApplyRelocations(self):
        # Don't assume VA's are sorted properly.
        # We sort them out, because the algorithm for rebuilding the relocated section assumes
        # the relocation's addresses are from low to high addresses.
        self._Relocs.sort(SortRelocCallback)
        # Hold relocations by their sections.
        Secs = [[] for i in xrange(len(self.Sections))]
        # Sort them into their corresponding section.
        for i in self._Relocs:
            Secs[i.Section.Index].append(i)
        # Eliminate empty sections (which don't have relocations).
        Secs = filter(len, Secs)
        # Now for every section apply its changes
        for Sec in Secs:
            OldVA = 0
            # TmpBin will be used for efficiency in order to apply the patch to Python buffers.
            TmpBin = cStringIO.StringIO()
            # Get its section.
            SecVA = Sec[0].Section.VA
            PageSec = self.GetSectionByVA(SecVA)
            # Patches the required addresses.
            for i in Sec:
                # Copy the buffer till this address.
                buf = PageSec.Data[OldVA:i.RelocAddr - SecVA]
                if len(buf):
                    TmpBin.write(buf)
                if (self.OptMagic == MAGIC_PE32):
                    # Calc next offset.
                    OldVA = i.RelocAddr - SecVA + 4
                    # Append the new relocated value.
                    TmpBin.write(struct.pack("<L", i.OriginalValue + self.Delta))
                else:
                    # Calc next offset.
                    OldVA = i.RelocAddr - SecVA + 8
                    # Append the new relocated value.
                    TmpBin.write(struct.pack("<Q", i.OriginalValue + self.Delta))
            # Append any tail buffer left.
            TmpBin.write(PageSec.Data[OldVA:])
            # And use the new section binary.
            PageSec.Data = TmpBin.getvalue()
            TmpBin.close()

class Section(object):
    def __init__(self, Index, Name, VA, Flags, Bin):
        # Number of the section in the file.
        self.Index = Index
        self.Name = Name
        # Pointer to File Raw Data.
        self.VA = VA
        self.Flags = Flags
        self.Data = Bin
        self.Size = len(Bin)
    def __repr__(self):
        return "<section %s, VA = 0x%.8X, Flags = 0x%.8X, <0x%X bytes data>>" % (self.Name, self.VA, self.Flags, len(self.Data))

class Export(object):
    def __init__(self, fname, ord, va):
        # The VA in which the function sits.
        self.VA = va
        # Function name (if exists).
        if len(fname) == 0 or fname == None:
            self.Name = "<Unnamed>"
        self.Name = fname
        # Function ordinal.
        self.Ordinal = ord
    def __repr__(self):
        return "<Exported Function %s, Ordinal %d, VA 0x%.8X>" % (self.Name, self.Ordinal, self.VA)

class Import(object):
    def __init__(self, va, fname, modname):
        self.VA = va
        self.Name = fname
        self.ModuleName = modname
    def __repr__(self):
        return "<Imported Function %s.%s at 0x%.8X>" % (self.ModuleName[:self.ModuleName.rfind('.')], self.Name, self.VA)

class Relocation(object):
    def __init__(self, Section, PageVA, Offset, OriginalValue):
        self.Section = Section
        self.PageVA = PageVA
        self.Offset = Offset
        # Original value of the dword which isn't relocated yet.
        self.OriginalValue = OriginalValue
    def _get_reloc_address(self):
        return self.PageVA + self.Offset
    def __repr__(self):
        return "<Relocation at 0x%.8X, OrigVal=%08x>" % (self.RelocAddr, self.OriginalValue)
    RelocAddr = property(_get_reloc_address)

def SortRelocCallback(R1, R2):
    " Helper function for sorting all relocations' addresses. "
    res = R1.RelocAddr - R2.RelocAddr
    if res < 0:
        return -1
    elif res > 0:
        return 1
    return 0
    
def main():
    if (len(sys.argv) != 2) and (len(sys.argv) != 3):
        print os.path.split(sys.argv[0])[1] + " <PE file name> <new image base in hex>"
        return None
    filename = sys.argv[1]
    NewImageBase = None
    if (len(sys.argv) == 3):
        NewImageBase = int(sys.argv[2], 16)
    PEObj = PEFile(filename, NewImageBase)
    print "diSlib, http://ragestorm.net/distorm/\n"
    print "Image Base: 0x%08x, Code Size: 0x%x" % (PEObj.ImageBase, PEObj.CodeSize)
    print "Entry Point RVA: %08x" % PEObj.EntryPoint
    print "Sections:"
    for i in PEObj.Sections[:-1]:
        print "%d.Name: %s, VA: %x, Size: %x, Flags: %x" % (i.Index + 1, i.Name, i.VA, i.Size, i.Flags)
    if PEObj.Imports:
        print "Imports:"
        for i in PEObj.Imports:
            print i
    try:
        if PEObj.Exports:
            print "Exports:"
            for i in PEObj.Exports:
                print i
    except:
        # Ignore corrupted exports.
        pass
    if PEObj.Relocs:
        print "Relocations:"
        for i in PEObj.Relocs:
            print i

    try:
        # If diStorm isn't available, we won't disassemble anything.
        import distorm3

        DecodeType = distorm3.Decode32Bits
        if (PEObj.MachineType == IMAGE_FILE_MACHINE_AMD64):
            DecodeType = distorm3.Decode64Bits

        # Find code section and disassemble entry point routine.
        TextSec = PEObj.GetSectionByVA(PEObj.EntryPoint)
        if TextSec == None:
            return
        l = distorm3.Decode(PEObj.ImageBase + PEObj.EntryPoint, TextSec.Data[PEObj.EntryPoint - TextSec.VA:][:4*1024], DecodeType)
        for i in l:
            print "0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2])
            if ((i[2][:3] == "RET") or (i[2] == "INT 3") or (i[2][:3] == "JMP")):
                break
    except:
        pass

if (__name__ == "__main__"):
    main()
