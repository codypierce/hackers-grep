#!/usr/bin/env python

# pdbsymbols.py modified from pdbdump
# Copyright (C) 2009 https://code.google.com/p/pdbdump/

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys, os
import comtypes
import comtypes.client
import winnt

msdia = comtypes.client.GetModule( r'msdia80.dll' )

from comtypes.gen.Dia2Lib import *

PTRSIZE = 4 # sizeof(void*)/sizeof(char)
LOCATION_STR=('Null', 'Static', 'TLS', 'RegRel', 'ThisRel', 'Enregistered', 'BitField', 'Slot', 'IlRel', 'MetaData', 'Constant')

SymTagNull,         SymTagExe,          SymTagCompiland,    SymTagCompilandDetails, \
SymTagCompilandEnv, SymTagFunction,     SymTagBlock,        SymTagData, \
SymTagAnnotation,   SymTagLabel,        SymTagPublicSymbol, SymTagUDT, \
SymTagEnum,         SymTagFunctionType, SymTagPointerType,  SymTagArrayType, \
SymTagBaseType,     SymTagTypedef,      SymTagBaseClass,    SymTagFriend, \
SymTagFunctionArgType, SymTagFuncDebugStart, SymTagFuncDebugEnd, SymTagUsingNamespace, \
SymTagVTableShape,  SymTagVTable,       SymTagCustom,       SymTagThunk, \
SymTagCustomType,   SymTagManagedType,  SymTagDimension,    SymTagMax = range(32)
SYMTAG_STR  =('Null', 'Exe', 'Compiland', 'CompilandDetails', 'CompilandEnv', 'Function',
              'Block', 'Data', 'Annotation', 'Label', 'PublicSymbol', 'UDT', 'Enum',
              'FunctionType', 'PointerType', 'ArrayType', 'BaseType', 'Typedef',
              'BaseClass', 'Friend', 'FunctionArgType', 'FuncDebugStart', 'FuncDebugEnd',
              'UsingNamespace', 'VTableShape', 'VTable', 'Custom', 'Thunk', 'CustomType',
              'ManagedType', 'Dimension')

DataIsUnknown,      DataIsLocal,        DataIsStaticLocal,  DataIsParam, \
DataIsObjectPtr,    DataIsFileStatic,   DataIsGlobal,       DataIsMember, \
DataIsStaticMember, DataIsConstant = range(10)
DATAKIND_STR=('Unknown', 'Local', 'StaticLocal', 'Param', 'ObjectPtr', 'FileStatic', 'Global', 'Member', 'StaticMember', 'Constant')

UdtStruct, UdtClass, UdtUnion = range(3)
UDTKIND_STR = ('struct', 'class', 'union')

LocIsNull,      LocIsStatic,    LocIsTLS,   LocIsRegRel,    LocIsThisRel,   LocIsEnregistered, \
LocIsBitField,  LocIsSlot,      LocIsIlRel, LocInMetaData,  LocIsConstant,  LocTypeMax = range(12)

btNoType    = 0
btVoid      = 1
btChar      = 2
btWChar     = 3
btInt       = 6
btUInt      = 7
btFloat     = 8
btBCD       = 9
btBool      = 10
btLong      = 13
btULong     = 14
btCurrency  = 25
btDate      = 26
btVariant   = 27
btComplex   = 28
btBit       = 29
btBSTR      = 30
btHresult   = 31


CV_ARM_R0       = 10
CV_ARM_R1       = 11
CV_ARM_R2       = 12
CV_ARM_R3       = 13
CV_ARM_R4       = 14
CV_ARM_R5       = 15
CV_ARM_R6       = 16
CV_ARM_R7       = 17
CV_ARM_R8       = 18
CV_ARM_R9       = 19
CV_ARM_R10      = 20
CV_ARM_R11      = 21 # Frame pointer, if allocated
CV_ARM_R12      = 22
CV_ARM_SP       = 23 # Stack pointer
CV_ARM_LR       = 24 # Link Register
CV_ARM_PC       = 25 # Program counter
CV_ARM_CPSR     = 26 # Current program status register

CV_REG_EAX      =  17
CV_REG_ECX      =  18
CV_REG_EDX      =  19
CV_REG_EBX      =  20
CV_REG_ESP      =  21
CV_REG_EBP      =  22
CV_REG_ESI      =  23
CV_REG_EDI      =  24
CV_REG_EDXEAX   =  212

REGS_ARM={  CV_ARM_R0   :"r0",  CV_ARM_R1   :"r1",  CV_ARM_R2   :"r2",  CV_ARM_R3   :"r3",
            CV_ARM_R4   :"r4",  CV_ARM_R5   :"r5",  CV_ARM_R6   :"r6",  CV_ARM_R7   :"r7",
            CV_ARM_R8   :"r8",  CV_ARM_R9   :"r9",  CV_ARM_R10  :"r10", CV_ARM_R11  :"r11",
            CV_ARM_R12  :"r12", CV_ARM_SP   :"sp",  CV_ARM_LR   :"lr",  CV_ARM_PC   :"pc",
            CV_ARM_CPSR :"cpsr"}
REGS_386={  CV_REG_EAX:  "eax", CV_REG_ECX:  "ecx", CV_REG_EDX:  "edx", CV_REG_EBX:  "ebx",
            CV_REG_ESP:  "esp", CV_REG_EBP:  "ebp", CV_REG_ESI:  "esi", CV_REG_EDI:  "edi",
            CV_REG_EDXEAX: "edx:eax",}
REGS_X64={}
REG_NAMES={ 332:REGS_386, 448:REGS_ARM, 450:REGS_ARM, 512:REGS_X64}


CV_CALL_NEAR_C      = 0x00 #  near right to left push, caller pops stack
CV_CALL_NEAR_FAST   = 0x04 #  near left to right push with regs, callee pops stack
CV_CALL_NEAR_STD    = 0x07 #  near standard call
CV_CALL_NEAR_SYS    = 0x09 #  near sys call
CV_CALL_THISCALL    = 0x0b #  this call (this passed in register)
CALLCONV_STR = {
    CV_CALL_NEAR_C:    "__cdecl",
    CV_CALL_NEAR_FAST: "__fastcall",
    CV_CALL_NEAR_STD:  "__stdcall",
    CV_CALL_NEAR_SYS:  "__syscall",
    CV_CALL_THISCALL:  "__thiscall", }


nsNone = 0
nsfCaseSensitive = 0x1         # apply a case sensitive match
nsfCaseInsensitive = 0x2       # apply a case insensitive match
nsfFNameExt = 0x4              # treat names as paths and apply a filename.ext match
nsfRegularExpression = 0x8     # regular expression
nsfUndecoratedName = 0x10      # applies only to symbols that have both undecorated and decorated names
# predefined names for backward source compatibility
nsCaseSensitive = nsfCaseSensitive             # apply a case sensitive match
nsCaseInsensitive = nsfCaseInsensitive         # apply a case insensitive match
nsFNameExt = nsfCaseInsensitive | nsfFNameExt  # treat names as paths and apply a filename.ext match
nsRegularExpression = nsfRegularExpression | nsfCaseSensitive      # regular expression (using only '*' and '?')
nsCaseInRegularExpression = nsfRegularExpression | nsfCaseInsensitive  # case insensitive regular expression

class SymPublic:
    def __init__(self):
        self.location = None
        self.size = None
        self.undecorated_name = None
        self.name = None
        
class PdbFile:
    def __init__(self, pdb_file):
        self.pdb_file = pdb_file
        try:
            self.ds = comtypes.client.CreateObject( msdia.DiaSource )
        except:
            os.system('regsvr32 /s msdia80.dll')
            self.ds = comtypes.client.CreateObject( msdia.DiaSource )
        self.session = None
        self.public = []
        
    def __find_children(self, parent, symTag=SymTagNull, name=None, compareFlags=nsNone):
        for sym in parent.findChildren(symTag, name, compareFlags):
            yield sym.QueryInterface(IDiaSymbol)

    def __format_location(self, sym):
        if sym.locationType==LocIsStatic:           return "%08X" % sym.virtualAddresss
        elif sym.locationType==LocIsTLS:            pass # sym.virtualAddress
        elif sym.locationType==LocIsRegRel:         pass # (RegisterStr(sym), offsetstr(sym.offset))
        elif sym.locationType==LocIsThisRel:        pass # offsetstr(sym.offset)
        elif sym.locationType==LocIsEnregistered:   pass # RegisterStr(sym)
        elif sym.locationType==LocIsBitField:       pass # (sym.offset, sym.bitPosition, sym.length)
        elif sym.locationType==LocIsSlot:           pass # (sym.slot)
        elif sym.locationType==LocIsIlRel:          pass # sym.offset
        elif sym.locationType==LocInMetaData:       pass # sym.token
        elif sym.locationType==LocIsConstant:       pass # sym.value
        elif sym.locationType==LocIsNull:           pass
        else:                                       pass
        return None
            
    def __dump_symbol(self, sym):
        if sym.symTag==SymTagEnum:
            print "Asked to dump SymTagEnum"
        elif sym.symTag==SymTagTypedef:
            print "Asked to dump SymTagTypedef"
        elif sym.symTag==SymTagData:
            print "Asked to dump SymTagData"
        elif sym.symTag==SymTagFunction:
            print "Asked to dump SymTagFunction"
        elif sym.symTag==SymTagBaseClass:
            print "Asked to dump SymTagBaseClase"
        elif sym.symTag==SymTagUDT:
            print "Asked to dump SymTagUDT"
        elif sym.symTag==SymTagPublicSymbol:
            p = SymPublic()
            p.location = "%08X" % sym.virtualAddress
            p.size = sym.length
            p.undecorated_name = sym.undecoratedName
            p.name = sym.name
            return p
        else:
            o += '?ACHTUNG '+SYMTAG_STR[sym.symTag]
        return None
        
    def setup(self):
        if self.ds == None:
            print "[!] DiaSource not created"
            return False
                    
        try:
            self.ds.loadDataFromPdb(self.pdb_file)
        except:
            #ds.loadDataForExe(arg, '', None)
            pass

        self.session = self.ds.openSession()

        #ses.loadAddress = 0x00400000

    def dump_children(self, scope, symTag):
        o = ''
        for sym in self.__find_children(scope, symTag): #, None, nsfUndecoratedName
            self.public.append(self.__dump_symbol(sym))
        return o
    
    def dump_props(self, sym):
        for d in dir(sym):
            try:
                a = sym.__getattribute__(d)
            except:
                continue
            if  isinstance(a, int):
                print d, a
            elif isinstance(a, long):
                print d, a
            elif isinstance(a, str):
                print d, a
            elif isinstance(a, unicode):
                print d, a
                
    def get_public(self):
        if not self.session:
            print "[!] No session"
            return False
            
        # DUMP ALL PUBLICS
        self.dump_children(self.session.globalScope, SymTagPublicSymbol)
        for sym in self.__find_children(self.session.globalScope, SymTagPublicSymbol):
            #self.dump_props(sym)
            self.public.append(self.__dump_symbol(sym))


if __name__=='__main__':
    arg = sys.argv[1]
    pf = PdbFile(arg)
    pf.setup()
    pf.get_public()
    for p in pf.public:
        print "%s: %10d | %s" % (p.location, p.size, p.undecorated_name)
