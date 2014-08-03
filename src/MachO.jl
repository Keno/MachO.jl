######### MachO.jl - An implementation of the MachO File format ################
#
## General design philosophy
#
# All methods should operate on seekable IO object. In particular this means
# that the basic interface buffers as little as possible (e.g. the MachOHandle)
# object does not contain the mach_header.
#
################################################################################

module MachO

# For printing
import Base: show, print, bytestring

# This package implements the ObjFileBase interface
import ObjFileBase
import ObjFileBase: sectionsize, sectionoffset, readheader, ObjectHandle, readmeta

# Reexports from ObjFileBase
export sectionsize, sectionoffset, readheader, readmeta

export readmeta, readheader, LoadCmds, Sections, Symbols, symname, segname,
    debugsections

############################ Data Structures ###################################


#
# Contains all constants defined in the MachO standard with values taken
# from the appropriate headers on MacOS 10.9
#
include("constants.jl")

#
# StrPack is used mostly for endianness handling
#
using StrPack

# MachOHandle

#
# Represents the actual MachO file
#
immutable MachOHandle{T<:IO} <: ObjectHandle
    # The IO object. This field is speciallized on to avoid dispatch performance
    # hits, especially when operating on an IOBuffer, which is an important
    # usecase for in-memory files
    io::T
    # position(io) of the start of the file in the io stream.
    start::Int
    # Whether or not the data is bswap'ed in memory (i.e. has different
    # endianness)
    bswapped::Bool
    # Whether or not the file is 64bit
    is64::Bool
end

endianness(oh::MachOHandle) = oh.bswapped ? :SwappedEndian : :NativeEndian

MachOHandle{T<:IO}(io::T,start::Int,bswapped::Bool,is64::Bool) =
    MachOHandle{T}(io,start,bswapped,is64)

function show(io::IO,h::MachOHandle)
    print(io,"MachO handle (")
    print(io,h.is64?"64-bit":"32-bit")
    h.bswapped && print(io,",swapped")
    print(io,")")
end


############################ Data Structures ###################################
#
# This section contains data structures as defined by the MachO specification.
# They are used below to acutally read in the data and may be ocassionally
# referenced from interface structs where this is convenient and no other
# interface exists
#
################################################################################

abstract MachOLC

@struct immutable mach_header
    magic::Uint32
    cputype::Uint32
    cpusubtype::Uint32
    filetype::Uint32
    ncmds::Uint32
    sizeofcmds::Uint32
    flags::Uint32
end

@struct immutable mach_header_64
    magic::Uint32
    cputype::Uint32
    cpusubtype::Uint32
    filetype::Uint32
    ncmds::Uint32
    sizeofcmds::Uint32
    flags::Uint32
    reserved::Uint32
end

@struct immutable load_command
    cmd::Uint32
    cmdsize::Uint32
end

# A 16 byte string, represented as a Uint128, but shown as a string
@struct immutable small_fixed_string
    string::Uint128
end

@struct immutable uuid_command <: MachOLC
    uuid::Uint128
end

@struct immutable segment_command <: MachOLC
    segname::small_fixed_string
    vmaddr::Uint32
    vmsize::Uint32
    fileoff::Uint32
    filesize::Uint32
    maxprot::Uint32
    initprot::Uint32
    nsects::Uint32
    flags::Uint32
end

@struct immutable segment_command_64 <: MachOLC
    segname::small_fixed_string
    vmaddr::Uint64
    vmsize::Uint64
    fileoff::Uint64
    filesize::Uint64
    maxprot::Cint
    initprot::Cint
    nsects::Uint32
    flags::Uint32
end

@struct immutable section <: ObjFileBase.Section{MachOHandle}
    sectname::small_fixed_string
    segname::small_fixed_string
    addr::Uint32
    size::Uint32
    offset::Uint32
    align::Uint32
    reloff::Uint32
    nreloc::Uint32
    flags::Uint32
    reserved1::Uint32
    reserved2::Uint32
end

@struct immutable section_64 <: ObjFileBase.Section{MachOHandle}
    sectname::small_fixed_string
    segname::small_fixed_string
    addr::Uint64
    size::Uint64
    offset::Uint32
    align::Uint32
    reloff::Uint32
    nreloc::Uint32
    flags::Uint32
    reserved1::Uint32
    reserved2::Uint32
end

@struct immutable symtab_command <: MachOLC
    symoff::Uint32
    nsyms::Uint32
    stroff::Uint32
    strsize::Uint32
end

@struct immutable dysymtab_command <: MachOLC
    ilocalsym::Uint32
    nlocalsym::Uint32
    iextdefsym::Uint32
    nextdefsym::Uint32
    iundefsym::Uint32
    nundefsym::Uint32
    tocoff::Uint32
    ntoc::Uint32
    modtaboff::Uint32
    nmodtab::Uint32
    extrefsymoff::Uint32
    nextrefsyms::Uint32
    indirectsymoff::Uint32
    nindirectsyms::Uint32
    extreloff::Uint32
    nextrel::Uint32
    locreloff::Uint32
    nlocrel::Uint32
end

@struct immutable version_min_macosx_command <: MachOLC
    version::Uint32
    sdk::Uint32
end

@struct immutable lc_str
    offset::Uint32
end

@struct immutable dylib
    name::lc_str
    timestamp::Uint32
    current_version::Uint32
    compatibilty::Uint32
end

@struct immutable dylib_command <: MachOLC
    dylib::dylib
end

@struct immutable dyld_info_command <: MachOLC
    rebase_off::Uint32
    rebase_size::Uint32
    bind_off::Uint32
    bind_size::Uint32
    weak_bind_off::Uint32
    weak_bind_size::Uint32
    lazy_bind_off::Uint32
    lazy_bind_size::Uint32
    export_off::Uint32
    export_size::Uint32
end

@struct immutable source_version_command <: MachOLC
    version::Uint64
end

@struct immutable linkedit_data_command <: MachOLC
    offset::Uint32
    size::Uint32
end

@struct immutable sub_framework_command <: MachOLC
    umbrella::lc_str
end

@struct immutable nlist <: ObjFileBase.SymtabEntry{MachOHandle}
    n_strx::Uint32
    n_type::Uint8
    n_sect::Uint8
    n_desc::Uint16
    n_value::Uint32
end

@struct immutable nlist_64 <: ObjFileBase.SymtabEntry{MachOHandle}
    n_strx::Uint32
    n_type::Uint8
    n_sect::Uint8
    n_desc::Uint16
    n_value::Uint64
end

@struct immutable fat_header
    nfat_arch::Uint32
end

@struct immutable fat_arch
    cputype::Uint32
    cpusubtype::Uint32
    offset::Uint32
    size::Uint32
    align::Uint32
end

########################### Printing Data Structures ###########################
#
# This prints the basic Mach-O data structures above. Where there is no good
# reason not to, the output matches that of otool.
#
################################################################################

function bytestring(x::small_fixed_string)
    a8 = reinterpret(Uint8,[x.string])
    z = findfirst(a8,0)
    ASCIIString(a8[1:(z == 0 ? length(a8) : z-1)])
end
show(io::IO,x::small_fixed_string) = show(io,bytestring(x))
print(io::IO,x::small_fixed_string) = print(io,bytestring(x))

==(x::small_fixed_string,y::String) = bytestring(x) == y
==(x::String,y::small_fixed_string) = y==x

*(a::ASCIIString,b::small_fixed_string) = a*bytestring(b)

function printfield(io::IO,string,fieldlength)
    print(io," "^max(fieldlength-length(string),0))
    print(io,string)
end

# TODO: Implement
printflags(io,flags) = nothing

function show(io::IO,h::Union(mach_header,mach_header_64))
    print(io,"Mach header (",isa(h,mach_header_64)?"64-bit":"32-bit",")\n")
    print(io,"")
    print(io,"""
          magic  cputype cpusubtype     filetype ncmds sizeofcmds    flags
    """)
    printfield(io,MAGICS[h.magic],11)
    printfield(io,CPUTYPES[h.cputype],9)
    print(io," "^11)
    # TODO: cpusubtype printing
    #printfield(io,CPUSUBTYPES[h.cpusubtype],8)
    # otool has caps == h.cpusubtype & CPU_SUBTYPE_MASK here, I don't consider
    # it all that useful. If somebody has a strong case why it's useful to have
    # that extra field, prlease submit a PR!
    printfield(io,FILETYPES[h.filetype],13)
    printfield(io,dec(h.ncmds),6)
    printfield(io,dec(h.sizeofcmds),11)
    printflags(io,h.flags)
end

const VM_PROT_READ      =   0x01 # read permission
const VM_PROT_WRITE     =   0x02 # write permission
const VM_PROT_EXECUTE   =   0x04 # execute permission

protstr(prot) = string(
    (prot & VM_PROT_READ)    > 0 ? "r" : "",
    (prot & VM_PROT_WRITE)   > 0 ? "w" : "",
    (prot & VM_PROT_EXECUTE) > 0 ? "x" : "")

function segflags(flags)
    if flags == 0
        return "(none)"
    else
        return "(unimplemented)"
    end
end

#     printentry(io,"offset",dec(l.offset))
#    printentry(io,"align","2^",l.align," (",2^l.align,")")

printentry(io::IO,header,values...) = (printfield(io,header,15);println(io," ",values...))
# Showing Load commands
function show(io::IO,l::Union(segment_command_64,segment_command))
    println(io,"Load Command (",isa(l,segment_command_64)?"SEGMENT_64":
        "SEGMENT","):")

    printentry(io,"name",l.segname)
    printentry(io,"addr",l.vmaddr)
    printentry(io,"size",l.vmsize)
    printentry(io,"fileoff",dec(l.fileoff))
    printentry(io,"filesize",dec(l.filesize))
    printentry(io,"maxprot",protstr(l.maxprot))
    printentry(io,"initprot",protstr(l.initprot))
    printentry(io,"nsects",dec(l.nsects))
    printentry(io,"flags",segflags(l.flags))
end

function sattrs(attributes)
    strings = ASCIIString[]
    for (k,v) in SECATTRS
        if attributes & k > 0
            push!(strings, v)
        end
    end
    join(strings,",")
end


function show(io::IO, s::Union(section,section_64))
    #function body
    println(io,"  Section:")

    printentry(io,"sectname",s.sectname)
    printentry(io,"segname",s.segname)
    printentry(io,"addr","0x",hex(s.addr,2*sizeof(s.addr)))
    printentry(io,"size","0x",hex(s.size,2*sizeof(s.addr)))
    printentry(io,"offset",dec(s.offset))
    printentry(io,"align","2^",s.align," (",2^s.align,")")
    printentry(io,"reloff",s.reloff)
    printentry(io,"nreloc",s.nreloc)
    printentry(io,"type",SECTYPES[s.flags&SECTION_TYPE])
    printentry(io,"attributes",sattrs(s.flags&SECTION_ATTRIBUTES))
end

function show(io::IO,l::symtab_command)
    println(io,"Load Command (SYMTAB):")
    printentry(io,"symoff",dec(l.symoff))
    printentry(io,"nsyms",dec(l.nsyms))
    printentry(io,"stroff",dec(l.stroff))
    printentry(io,"strsize",dec(l.strsize))
end

function show(io::IO,l::dysymtab_command)
    println(io,"Load Command (DYSYMTAB):")
    printentry(io,"ilocalsym",dec(l.ilocalsym))
    printentry(io,"nlocalsym",dec(l.nlocalsym))
    printentry(io,"iextdefsym",dec(l.iextdefsym))
    printentry(io,"nextdefsym",dec(l.nextdefsym))
    printentry(io,"iundefsym",dec(l.iundefsym))
    printentry(io,"nundefsym",dec(l.nundefsym))
    printentry(io,"tocoff",dec(l.tocoff))
    printentry(io,"ntoc",dec(l.ntoc))
    printentry(io,"modtaboff",dec(l.modtaboff))
    printentry(io,"nmodtab",dec(l.nmodtab))
    printentry(io,"extrefsymoff",dec(l.extrefsymoff))
    printentry(io,"nextrefsyms",dec(l.nextrefsyms))
    printentry(io,"indirectsymoff",dec(l.indirectsymoff))
    printentry(io,"nindirectsyms",dec(l.nindirectsyms))
    printentry(io,"extreloff",dec(l.extreloff))
    printentry(io,"nextrel",dec(l.nextrel))
    printentry(io,"locreloff",dec(l.locreloff))
    printentry(io,"nlocrel",dec(l.nlocrel))
end

function decodeversion(io::IO, version::Uint32)
    print(io,version>>16)
    print(io,'.')
    print(io,(version>>8)&0xFF)
    print(io,'.')
    print(io,version&0xFF)
end

function show(io::IO,l::version_min_macosx_command)
    println(io,"Load Command (VERSION_MIN_MACOSX):")
    printentry(io,"version",sprint(decodeversion,l.version))
    printentry(io,"sdk",sprint(decodeversion,l.sdk))
end

################################ Interface #####################################

import Base: show,
    # IO methods
    read, write, seek, seekstart, position, readuntil, readbytes,
    # Iteration
    start, next, done,
    # Indexing
    length, getindex

import StrPack: unpack, pack

#
# Note that this function is different from ObjFileBase.readmeta
# Constructs and initializes the MachOHandle object
#
function readmeta(io::IO)
    start = position(io)
    magic = read(io,Uint32)
    if magic == MH_MAGIC
        return MachOHandle(io,start,false,false)
    elseif magic == MH_CIGAM
        return MachOHandle(io,start,true,false)
    elseif magic == MH_MAGIC_64
        return MachOHandle(io,start,false,true)
    elseif magic == MH_CIGAM_64
        return MachOHandle(io,start,true,true)
    elseif magic == FAT_CIGAM || magic == FAT_MAGIC
        return FatMachOHandle(io,start)
    else
        error("Invalid Magic ($(hex(magic)))!")
    end
end
ObjFileBase.readmeta(io::IO,::Type{MachOHandle}) = readmeta(io)

function readloadcmd(h::MachOHandle)
    cmd = unpack(h,load_command)
    ccmd = cmd.cmd & ~LC_REQ_DYLD
    if ccmd == LC_UUID
        return (cmd,unpack(h, uuid_command))
    elseif ccmd == LC_SEGMENT
        return (cmd,unpack(h, segment_command))
    elseif ccmd == LC_SEGMENT_64
        return (cmd,unpack(h, segment_command_64))
    elseif ccmd == LC_SYMTAB
        return (cmd,unpack(h, symtab_command))
    elseif ccmd == LC_DYSYMTAB
        return (cmd,unpack(h, dysymtab_command))
    elseif ccmd == LC_VERSION_MIN_MACOSX
        return (cmd,unpack(h, version_min_macosx_command))
    elseif ccmd == LC_ID_DYLIB || ccmd == LC_LOAD_DYLIB ||
        cmd.cmd == LC_REEXPORT_DYLIB || ccmd == LC_LOAD_UPWARD_DYLIB
        return (cmd,unpack(h, dylib_command))
    elseif ccmd == LC_DYLD_INFO
        return (cmd,unpack(h, dyld_info_command))
    elseif ccmd == LC_SOURCE_VERSION
        return (cmd,unpack(h, source_version_command))
    elseif ccmd == LC_CODE_SIGNATURE || ccmd == LC_SEGMENT_SPLIT_INFO ||
            ccmd == LC_FUNCTION_STARTS || ccmd == LC_DATA_IN_CODE ||
            ccmd == LC_DYLIB_CODE_SIGN_DRS
        return (cmd,unpack(h, linkedit_data_command))
    elseif ccmd == LC_SUB_FRAMEWORK
        return (cmd,unpack(h,sub_framework_command))
    else
        error("Unimplemented load command $(LCTYPES[cmd.cmd]) (0x$(hex(cmd.cmd)))")
    end
end

## Iteration

import Base: eltype

# Iterate over the load commands of a file
# If the header has
# already been read, it may be passed to the constructor. Optionally
# the start address of the load commands may also be passed in
# passed in. If a header is passed, it is assumed that the start address
# is the current position of the stream. Otherwise, it will be determined when
# reading the header.
immutable LoadCmds
    h::MachOHandle
    start::Uint64
    ncmds::Uint32
    sizeofcmds::Uint32
end

immutable LoadCmd{T<:MachOLC}
    h::MachOHandle
    off::Uint64
    cmd::T
end

show{T}(io::IO, x::LoadCmd{T}) = (print(io,"0x",hex(x.off,8),":\n "); show(io,x.cmd); print(io,'\n'))

LoadCmd{T<:MachOLC}(h::MachOHandle, off::Uint64, cmd::T) = LoadCmd{T}(h,off,cmd)
eltype{T<:MachOLC}(::LoadCmd{T}) = T

function LoadCmds(h::MachOHandle, header = nothing, start = -1)
    if header === nothing
        header = readheader(h)
    end
    if start == -1
        start = position(h)
    end
    LoadCmds(h,start,header.ncmds,header.sizeofcmds)
end

# A tuple of the position before the current load command,
# the number of the load command and the size of the current load
# command. I.e. the next load command will be found at state[1]+state[3]
start(l::LoadCmds) = (l.start,0,0)
seek(l::LoadCmds,state) = seek(l.h,state[1]+state[3])
function next(l::LoadCmds,state)
    seek(l,state)
    cmdh,cmd = readloadcmd(l.h)
    (LoadCmd(l.h,state[1]+state[3],cmd),(state[1]+state[3],state[2]+1,cmdh.cmdsize))
end
done(l::LoadCmds,state) = state[2] >= l.ncmds

# Access to sections

typealias segment_commands Union(segment_command_64,segment_command)

immutable Sections
    h::MachOHandle
    command::segment_commands
    start::Int
    function Sections(h::MachOHandle, segment::segment_commands, start=-1)
        if start==-1
            start = position(h)
        end
        new(h,segment,start)
    end
    function Sections(segment::LoadCmd)
        if !(eltype(segment) <: segment_commands)
            error("Load command is not a segment")
        end
        start = segment.off + sizeof(eltype(segment)) + sizeof(load_command)
        new(segment.h,segment.cmd,start)
    end
end

length(s::Sections) = s.command.nsects
function getindex(s::Sections,n)
    if n < 1 || n > length(s)
        throw(BoundsError())
    end
    sT = isa(s.command,segment_command_64) ? section_64 : section
    seek(s.h,s.start + (n-1)*sizeof(sT))
    unpack(s.h, sT)
end

start(s::Sections) = 1
done(s::Sections,n) = n > length(s)
next(s::Sections,n) = (s[n],n+1)


for f in (:read,:readuntil,:write)
    @eval $(f){T<:IO}(io::MachOHandle{T},args...) = $(f)(io.io,args...)
end
readbytes{T<:IO}(io::MachOHandle{T},num::Integer) = readbytes(io.io,num)


seek{T<:IO}(io::MachOHandle{T},pos::Integer) = seek(io.io,io.start+pos)
seekstart(io::MachOHandle) = seek(io.io,io.start)
position{T<:IO}(io::MachOHandle{T}) = position(io.io)-io.start

unpack{T,ioT<:IO}(h::MachOHandle{ioT},::Type{T}) =
    unpack(h.io,T,h.bswapped ? :SwappedEndian : :NativeEndian)

pack{T,ioT<:IO}(h::MachOHandle{ioT},::Type{T}) =
    pack(h.io,T,h.bswapped ? :SwappedEndian : :NativeEndian)

function readheader(h::MachOHandle)
    seekstart(h)
    unpack(h,h.is64 ? mach_header_64 : mach_header)
end

sectionsize(sect::Union(section,section_64)) = sect.size
sectionoffset(sect::Union(section,section_64)) = sect.offset

# Access to Symbols
immutable Symbols
    h::MachOHandle
    command::symtab_command
    function Symbols(h::MachOHandle, segment::symtab_command)
        new(h,segment,start)
    end
    function Symbols(lc::LoadCmd{symtab_command})
        new(lc.h,lc.cmd)
    end
end

start(s::Symbols) = 1
done(s::Symbols,n) = n > length(s)
next(s::Symbols,n) = (s[n],n+1)

length(s::Symbols) = s.command.nsyms
function getindex(s::Symbols,n)
    if n < 1 || n > length(s)
        throw(BoundsError())
    end
    sT = s.h.is64 ? nlist_64 : nlist
    seek(s.h,s.command.symoff + (n-1)*sizeof(sT))
    unpack(s.h, sT)
end

function strtable_lookup(io::MachOHandle,command::symtab_command,offset)
    seek(io,command.stroff+offset)
    strip(readuntil(io,'\0'),'\0')
end

symname(io::MachOHandle,command::symtab_command,sym) = strtable_lookup(io, command, sym.n_strx)
symname(x::LoadCmd{symtab_command}, sym) = symname(x.h, x.cmd, sym)
segname(x::Union(segment_command_64,section_64)) = x.segname
segname(x::LoadCmd{segment_command_64}) = segname(x.cmd)
sectname(x::section_64) = x.sectname

### Fat Handle
immutable FatMachOHandle
    io::IO
    start::Uint64
    header::fat_header
    archs::Vector{fat_arch}
end

function FatMachOHandle(io,start)
    header = unpack(io,fat_header,:BigEndian)
    archs = Array(fat_arch,header.nfat_arch)
    for i in 1:header.nfat_arch
        archs[i] = unpack(io,fat_arch,:BigEndian)
    end
    FatMachOHandle(io,start,header,archs)
end

function getindex(h::FatMachOHandle,i)
    seek(h.io,h.start + h.archs[i].offset)
    readmeta(h.io,MachOHandle)
end

### Compact Unwind Support

include("compact_unwind.jl")

### DWARF support

using DWARF

function debugsections{T<:segment_commands}(seg::LoadCmd{T})
    sects = collect(Sections(seg))
    snames = map(sectname,sects)
    sections = Dict{ASCIIString,section_64}()
    for i in 1:length(snames)
        # remove leading "__"
        ind = findfirst(DWARF.DEBUG_SECTIONS,bytestring(snames[i])[3:end])
        if ind != 0
            sections[DWARF.DEBUG_SECTIONS[ind]] = sects[i]
        end
    end
    sections
end

end # module
