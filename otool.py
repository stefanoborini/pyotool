import uuid
import struct
import enum

class Magic(enum.Enum):
    MH_MAGIC_64 = 0xfeedfacf

class Filetype(enum.Enum):
    MH_OBJECT      = 0x1
    MH_EXECUTE     = 0x2
    MH_FVMLIB      = 0x3
    MH_CORE        = 0x4
    MH_PRELOAD     = 0x5
    MH_DYLIB       = 0x6
    MH_DYLINKER    = 0x7
    MH_BUNDLE      = 0x8
    MH_DYLIB_STUB  = 0x9
    MH_DSYM        = 0xa
    MH_KEXT_BUNDLE = 0xb

CPU_ARCH_MASK = 0xff000000
CPU_ARCH_ABI64 = 0x01000000

class CpuType(enum.Enum):
    CPU_TYPE_ANY = -1
    CPU_TYPE_VAX = 1
    CPU_TYPE_MC680x0 = 6
    CPU_TYPE_X86 = 7
    CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
    CPU_TYPE_MC98000 = 10
    CPU_TYPE_HPPA = 11
    CPU_TYPE_ARM = 12
    CPU_TYPE_MC88000 = 13
    CPU_TYPE_SPARC = 14
    CPU_TYPE_I860 = 15
    CPU_TYPE_POWERPC = 18
    CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64

CPU_SUBTYPE_MASK = 0xff000000
CPU_SUBTYPE_LIB64 = 0x80000000
LC_REQ_DYLD = 0x80000000

class CpuSubtype(enum.Enum):
    CPU_SUBTYPE_MULTIPLE      = -1
    CPU_SUBTYPE_LITTLE_ENDIAN = 0
    CPU_SUBTYPE_BIG_ENDIAN    = 1

class Command(enum.Enum):
    LC_SEGMENT = 0x1
    LC_SYMTAB =  0x2
    LC_SYMSEG  = 0x3
    LC_THREAD  = 0x4
    LC_UNIXTHREAD =  0x5
    LC_LOADFVMLIB =  0x6
    LC_IDFVMLIB =0x7
    LC_IDENT    =0x8
    LC_FVMFILE  =0x9
    LC_PREPAGE     = 0xa
    LC_DYSYMTAB =0xb
    LC_LOAD_DYLIB =  0xc
    LC_ID_DYLIB =0xd
    LC_LOAD_DYLINKER =0xe
    LC_ID_DYLINKER  =0xf
    LC_PREBOUND_DYLIB =0x10
    LC_ROUTINES =0x11
    LC_SUB_FRAMEWORK =0x12
    LC_SUB_UMBRELLA =0x13
    LC_SUB_CLIENT   =0x14
    LC_SUB_LIBRARY  =0x15
    LC_TWOLEVEL_HINTS =0x16
    LC_PREBIND_CKSUM  =0x17
    LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)
    LC_SEGMENT_64  = 0x19
    LC_ROUTINES_64 = 0x1a
    LC_UUID    = 0x1b
    LC_RPATH      =  (0x1c | LC_REQ_DYLD)
    LC_CODE_SIGNATURE =0x1d
    LC_SEGMENT_SPLIT_INFO =0x1e
    LC_REEXPORT_DYLIB = (0x1f | LC_REQ_DYLD)
    LC_LAZY_LOAD_DYLIB =0x20
    LC_ENCRYPTION_INFO= 0x21
    LC_DYLD_INFO   = 0x22
    LC_DYLD_INFO_ONLY = (0x22|LC_REQ_DYLD)
    LC_LOAD_UPWARD_DYLIB = (0x23 | LC_REQ_DYLD)
    LC_VERSION_MIN_MACOSX =0x24
    LC_VERSION_MIN_IPHONEOS =0x25
    LC_FUNCTION_STARTS =0x26
class Flags(enum.Enum):
    MH_NOUNDEFS       =  0x1
    MH_INCRLINK	      = 0x2
    MH_DYLDLINK	      = 0x4
    MH_BINDATLOAD	  = 0x8
    MH_PREBOUND	      = 0x10
    MH_SPLIT_SEGS     = 0x20
    MH_LAZY_INIT      = 0x40
    MH_TWOLEVEL       = 0x80
    MH_FORCE_FLAT     = 0x100
    MH_NOMULTIDEFS    = 0x200
    MH_NOFIXPREBINDING = 0x400
    MH_PREBINDABLE    = 0x800
    MH_ALLMODSBOUND   = 0x1000
    MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000
    MH_CANONICAL      = 0x4000
    MH_WEAK_DEFINES   = 0x8000
    MH_BINDS_TO_WEAK  = 0x10000
    MH_ALLOW_STACK_EXECUTION = 0x20000
    MH_ROOT_SAFE      = 0x40000
    MH_SETUID_SAFE    = 0x80000
    MH_NO_REEXPORTED_DYLIBS = 0x100000
    MH_PIE           = 0x200000
    MH_DEAD_STRIPPABLE_DYLIB = 0x400000
    MH_HAS_TLV_DESCRIPTORS = 0x800000
    MH_NO_HEAP_EXECUTION  = 0x1000000

class Struct:

    def structFmt(self):
        raise NotImplementedError()

    def size(self):
        return struct.calcsize(self.structFmt())

class MachHeader64(Struct):
    def __init__(self, data, offset):
        self.offset = offset
        self._header = struct.unpack_from(self.structFmt(),data)
        self.ncmds = self._header[4]

    def structFmt(self):
        return "IiiIIIII"

    def __str__(self):
        out  = "mach_header_64 {\n"
        out += "   magic = %s,\n" % Magic(int(self._header[0])).name
        out += "   cputype = %s,\n" % CpuType(int(self._header[1])).name
        out += "   cpusubtype = %s,\n" % str(int(self._header[2]))
        out += "   filetype = %s,\n" % Filetype(int(self._header[3])).name
        out += "   ncmds = %s,\n" % str(int(self._header[4]))
        out += "   sizeofcmds = %s,\n" % str(int(self._header[5]))
        out += "   flags = %s,\n" % str(self._splitFlags(int(self._header[6])))
        out += "   reserved = %s,\n" % str(int(self._header[7]))
        out += "};\n"
        return out

    def _splitFlags(self, flags):
        result = []
        for flag in Flags:
            if flags & int(flag.value):
                result.append(flag)
        return result


class LoadCommand(Struct):
    def __init__(self, data, offset):
        self._struct = struct.unpack_from(self.structFmt(),data, offset=offset)
        self.offset = offset
        self.cmd = Command(self._struct[0])
        self.cmdsize = self._struct[1]

    def structFmt(self):
        return "II"

    def __str__(self):
        out = str(self.offset) + " load_command { "
        command_str = str(Command(self._struct[0]).name)
        if self._struct[0] & LC_REQ_DYLD:
            command_str += ' | LC_REQ_DYLD'
        out += "cmd = "+command_str+", cmdsize = "+str(self._struct[1])+" };\n"
        return out

class UuidCommand(Struct):
    def structFmt(self):
        return "II16B"

    def __init__(self, data, offset):
        self._struct = struct.unpack_from(self.structFmt(),data, offset=offset)
        self.offset = offset
        self.cmdsize = self._struct[1]
        print(self._struct)
        self._uuid = uuid.UUID(int=int.from_bytes(self._struct[2:], byteorder="big"))
        print(self._uuid)

    def __str__(self):
        out = str(self.offset) + " uuid_command { "
        out += "uuid = "+str(self._uuid)+" };\n"
        return out

class MachO:
    def __init__(self, filename):
        self._filename = filename
        data = open(self._filename,"rb").read()
        self._header = MachHeader64(data, 0)
        self._load_commands = []
        for i in range(self._header.ncmds):
            cmd = LoadCommand(data, offset=self._header.size()+sum([x.cmdsize for x in self._load_commands]))
            print(cmd.cmd)
            if cmd.cmd == Command.LC_UUID:
                cmd = UuidCommand(data, offset = cmd.offset)
            self._load_commands.append(cmd)

    def __str__(self):
        out = str(self._header)
        for cmd in self._load_commands:
            out += str(cmd)
        return out

    def header(self):
        return self._header

    def loadCommands(self):
        return self._load_commands

print(MachO("a.out"))
