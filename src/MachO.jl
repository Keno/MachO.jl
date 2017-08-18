######### MachO.jl - An implementation of the MachO File format ################
#
## General design philosophy
#
# All methods should operate on seekable IO object. In particular this means
# that the basic interface buffers as little as possible (e.g. the MachOHandle
# object does not contain the mach_header).
#
################################################################################

__precompile__()
module MachO

# For printing
import Base: show, print, unsafe_string, showcompact, readuntil

# For endianness-handling
using StructIO
import StructIO: unpack

# This package implements the ObjFileBase interface
import ObjFileBase
import ObjFileBase: sectionsize, sectionoffset, readheader, ObjectHandle, readmeta,
    strtab_lookup, debugsections, endianness, load_strtab, deref, sectionname,
    sectionaddress, handle, symbolnum, printfield, symname, symbolvalue, isundef,
    intptr, isBSS

# For MachO datatypes (e.g. fixed size string)
import Base: ==, *

# Reexports from ObjFileBase
export sectionsize, sectionoffset, readheader, readmeta,
    debugsections

export LoadCmds, symname, segname

# Tree Interface for visualization
using AbstractTrees

import AbstractTrees: children

############################ Data Structures ###################################


#
# Contains all constants defined in the MachO standard with values taken
# from the appropriate headers on MacOS 10.9
#
include("constants.jl")

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
__init__() = push!(ObjFileBase.ObjHandles, MachOHandle)
ObjFileBase.handle(handle::MachOHandle) = handle
Base.eof(handle::MachOHandle) = eof(handle.io)

endianness(oh::MachOHandle) = oh.bswapped ? :SwappedEndian : :NativeEndian
intptr(oh::MachOHandle) = oh.is64 ? UInt64 : UInt32

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

# Dummy lc that we use to return when we don't know what a certain load command is
immutable dummy_lc <: MachOLC
end

@io immutable mach_header
    magic::UInt32
    cputype::UInt32
    cpusubtype::UInt32
    filetype::UInt32
    ncmds::UInt32
    sizeofcmds::UInt32
    flags::UInt32
end

@io immutable mach_header_64
    magic::UInt32
    cputype::UInt32
    cpusubtype::UInt32
    filetype::UInt32
    ncmds::UInt32
    sizeofcmds::UInt32
    flags::UInt32
    reserved::UInt32
end
mach_header_64(magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags) =
    mach_header_64(magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,0)


@io immutable load_command
    cmd::UInt32
    cmdsize::UInt32
end

# A 16 byte string, represented as a UInt128, but shown as a string
@io immutable small_fixed_string
    string::UInt128
end

@io immutable uuid_command <: MachOLC
    uuid::UInt128
end

immutable thread_command <: MachOLC
    flavor::UInt32
    count::UInt32
    data::Vector{UInt}
end

@io immutable entry_point_command <: MachOLC
    cmdsize::UInt32
    entryoff::UInt64
    stacksize::UInt64
end

@io immutable segment_command <: MachOLC
    segname::small_fixed_string
    vmaddr::UInt32
    vmsize::UInt32
    fileoff::UInt32
    filesize::UInt32
    maxprot::UInt32
    initprot::UInt32
    nsects::UInt32
    flags::UInt32
end

@io immutable segment_command_64 <: MachOLC
    segname::small_fixed_string
    vmaddr::UInt64
    vmsize::UInt64
    fileoff::UInt64
    filesize::UInt64
    maxprot::Cint
    initprot::Cint
    nsects::UInt32
    flags::UInt32
end

@io immutable section <: ObjFileBase.Section{MachOHandle}
    sectname::small_fixed_string
    segname::small_fixed_string
    addr::UInt32
    size::UInt32
    offset::UInt32
    align::UInt32
    reloff::UInt32
    nreloc::UInt32
    flags::UInt32
    reserved1::UInt32
    reserved2::UInt32
end

@io immutable section_64 <: ObjFileBase.Section{MachOHandle}
    sectname::small_fixed_string
    segname::small_fixed_string
    addr::UInt64
    size::UInt64
    offset::UInt32
    align::UInt32
    reloff::UInt32
    nreloc::UInt32
    flags::UInt32
    reserved1::UInt32
    reserved2::UInt32
end
isBSS(sec::Union{section, section_64}) = (sec.flags & SECTION_TYPE) == S_ZEROFILL

@io immutable relocation_info <: ObjFileBase.Relocation{MachOHandle}
    address::Int32
    target::UInt32
end

@io immutable symtab_command <: MachOLC
    symoff::UInt32
    nsyms::UInt32
    stroff::UInt32
    strsize::UInt32
end
symtab_command() = symtab_command(0,0,0,0)

@io immutable dysymtab_command <: MachOLC
    ilocalsym::UInt32
    nlocalsym::UInt32
    iextdefsym::UInt32
    nextdefsym::UInt32
    iundefsym::UInt32
    nundefsym::UInt32
    tocoff::UInt32
    ntoc::UInt32
    modtaboff::UInt32
    nmodtab::UInt32
    extrefsymoff::UInt32
    nextrefsyms::UInt32
    indirectsymoff::UInt32
    nindirectsyms::UInt32
    extreloff::UInt32
    nextrel::UInt32
    locreloff::UInt32
    nlocrel::UInt32
end

@io immutable version_min_macosx_command <: MachOLC
    version::UInt32
    sdk::UInt32
end

immutable dylib_command <: MachOLC
    offset::UInt32
    timestamp::UInt32
    current_version::UInt32
    compatibilty::UInt32

    # Read in automatically, when possible, via offset
    name::AbstractString
end

immutable dylinker_command <: MachOLC
    name::AbstractString
end

@io immutable routines_command_64 <: MachOLC
    init_address::UInt64
    init_module::UInt64
    reserverd::NTuple{6, UInt64}
end

immutable sub_client_command  <: MachOLC
    name::AbstractString
end


# Read in a C string, until we reach the end of the string or max out at max_len
function read_unsafe_string(io, max_len)
    str = UInt8[]
    idx = 0
    c = read(io, UInt8)
    while c != 0x00 && idx < max_len
        push!(str, c)
        c = read(io, UInt8)
        idx += 1
    end
    return String(str)
end

function unpack_lcstr{ioT<:IO}(h::MachOHandle{ioT}, offset, min_offset, max_offset)
    # Perform sanity checking on offset; if it is too small or too large,
    # don't try to read the lc_str, just assign it "<lc_str offset corrupt>"
    if offset >= min_offset && offset < max_offset
        # Seek to the previously extracted offset, minus minlen
        skip(h.io, offset - min_offset)

        # Read in the cstring
        lc_str = read_unsafe_string(h.io, max_offset - offset)
    else
        # If we are outside the bounds, (either the string begins in the middle
        # of the rest of the structure, or it begins outside of this load command)
        # do not attempt to automatically read it
        lc_str = "<lc_str offset corrupt>"
    end
end


function unpack{ioT<:IO}(h::MachOHandle{ioT},::Type{dylib_command},cmdsize::UInt32)
    # Get the offset
    offset = unpack(h, UInt32)

    # Now get timestamp, current_version and compatibilty
    timestamp = unpack(h, UInt32)
    current_version = unpack(h, UInt32)
    compatibilty = unpack(h, UInt32)

    # Grab our name, if we can (e.g. if offset is within bounds)
    name = unpack_lcstr(h, offset, 6*sizeof(UInt32), cmdsize)
    return dylib_command(offset, timestamp, current_version, compatibilty, name)
end

function unpack{ioT<:IO}(h::MachOHandle{ioT},
    T::Union{Type{dylinker_command},Type{sub_client_command}},cmdsize::UInt32)
    offset = unpack(h, UInt32)
    return T(unpack_lcstr(h, offset, 6*sizeof(UInt32), cmdsize))
end

@io immutable dyld_info_command <: MachOLC
    rebase_off::UInt32
    rebase_size::UInt32
    bind_off::UInt32
    bind_size::UInt32
    weak_bind_off::UInt32
    weak_bind_size::UInt32
    lazy_bind_off::UInt32
    lazy_bind_size::UInt32
    export_off::UInt32
    export_size::UInt32
end

@io immutable source_version_command <: MachOLC
    version::UInt64
end

@io immutable linkedit_data_command <: MachOLC
    offset::UInt32
    size::UInt32
end

immutable sub_framework_command <: MachOLC
    offset::UInt32

    # Read in automatically, when possible, via offset
    umbrella::AbstractString
end

immutable rpath_command <: MachOLC
    offset::UInt32

    # Read in automatically, when possible, via offset
    path::AbstractString
end

for T in [sub_framework_command, rpath_command]
    @eval function unpack{ioT<:IO}(h::MachOHandle{ioT},::Type{$T},cmdsize::UInt32)
        # Get the offset
        offset = unpack(h, UInt32)

        # Grab our path if we can (e.g. if offset is within bounds)
        path = unpack_lcstr(h, offset, 3*sizeof(UInt32), cmdsize)
        return $T(offset, path)
    end
end

@io immutable nlist <: ObjFileBase.SymtabEntry{MachOHandle}
    n_strx::UInt32
    n_type::UInt8
    n_sect::UInt8
    n_desc::UInt16
    n_value::UInt32
end

@io immutable nlist_64 <: ObjFileBase.SymtabEntry{MachOHandle}
    n_strx::UInt32
    n_type::UInt8
    n_sect::UInt8
    n_desc::UInt16
    n_value::UInt64
end

@io immutable fat_header
    nfat_arch::UInt32
end

@io immutable fat_arch
    cputype::UInt32
    cpusubtype::UInt32
    offset::UInt32
    size::UInt32
    align::UInt32
end


########################### Printing Data Structures ###########################
#
# This prints the basic Mach-O data structures above. Where there is no good
# reason not to, the output matches that of otool.
#
################################################################################

function unsafe_string(x::small_fixed_string)
    a8 = reinterpret(UInt8,[x.string])
    z = findfirst(a8,0)
    String(a8[1:(z == 0 ? length(a8) : z-1)])
end
show(io::IO,x::small_fixed_string) = show(io,unsafe_string(x))
print(io::IO,x::small_fixed_string) = print(io,unsafe_string(x))

# These can all be made a lot faster if they ever show up in a profile
Base.isempty(x::small_fixed_string) = isempty(unsafe_string(x))
Base.length(x::small_fixed_string) = length(unsafe_string(x))

==(x::small_fixed_string,y::AbstractString) = unsafe_string(x) == y
==(x::AbstractString,y::small_fixed_string) = y==x

*(a::String,b::small_fixed_string) = a*unsafe_string(b)


# TODO: Implement
printflags(io,flags) = nothing

function show(io::IO,h::Union{mach_header,mach_header_64})
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
function show(io::IO,l::Union{segment_command_64,segment_command})
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
    strings = String[]
    for (k,v) in SECATTRS
        if attributes & k > 0
            push!(strings, v)
        end
    end
    join(strings,",")
end


function show(io::IO, s::Union{section,section_64})
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

function decodeversion(io::IO, version::UInt32)
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
    read, write, seek, seekstart, position,
    # Iteration
    start, next, done,
    # Indexing
    length, getindex



#
# Note that this function is different from ObjFileBase.readmeta
# Constructs and initializes the MachOHandle object
#
function readmeta(io::IO,::Type{MachOHandle})
    start = position(io)
    magic = read(io,UInt32)
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
        throw(ObjFileBase.MagicMismatch("Invalid Magic ($(hex(magic)))!"))
    end
end

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
            ccmd == LC_REEXPORT_DYLIB || ccmd == LC_LOAD_UPWARD_DYLIB ||
            ccmd == LC_LOAD_WEAK_DYLIB
        return (cmd,unpack(h, dylib_command, cmd.cmdsize))
    elseif ccmd == LC_ID_DYLINKER || ccmd == LC_LOAD_DYLINKER ||
            ccmd == LC_DYLD_ENVIRONMENT
        return (cmd,unpack(h, dylinker_command, cmd.cmdsize))
    elseif ccmd == LC_DYLD_INFO
        return (cmd,unpack(h, dyld_info_command))
    elseif ccmd == LC_SOURCE_VERSION
        return (cmd,unpack(h, source_version_command))
    elseif ccmd == LC_CODE_SIGNATURE || ccmd == LC_SEGMENT_SPLIT_INFO ||
            ccmd == LC_FUNCTION_STARTS || ccmd == LC_DATA_IN_CODE ||
            ccmd == LC_DYLIB_CODE_SIGN_DRS
        return (cmd,unpack(h, linkedit_data_command))
    elseif ccmd == LC_SUB_FRAMEWORK
        return (cmd,unpack(h, sub_framework_command, cmd.cmdsize))
    elseif ccmd == LC_RPATH
        return (cmd,unpack(h, rpath_command, cmd.cmdsize))
    elseif ccmd == LC_UNIXTHREAD
        flavor = read(h, UInt32)
        count = read(h, UInt32)
        data = read(h, UInt, div(cmd.cmdsize - 4sizeof(UInt32),sizeof(UInt)))
        return (cmd,thread_command(flavor, count, data))
    elseif ccmd == LC_MAIN
        return (cmd,unpack(h, entry_point_command))
    elseif ccmd == LC_ROUTINES_64
        return (cmd,unpack(h, routines_command_64))
    elseif ccmd == LC_SUB_CLIENT
        return (cmd,unpack(h, sub_client_command, cmd.cmdsize))
    else
        info("Unimplemented load command $(LCTYPES[ccmd]) (0x$(hex(ccmd)))")
        return (cmd,dummy_lc())
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
    start::UInt64
    ncmds::UInt32
    sizeofcmds::UInt32
end

immutable LoadCmd{T<:MachOLC}
    h::MachOHandle
    off::UInt64
    cmd_id::UInt32
    cmd::T
end
deref(lc::LoadCmd) = lc.cmd
handle(lc::LoadCmd) = lc.h

function children(lc::LoadCmd)
    isa(lc.cmd, segment_commands) ? Sections(lc) : ()
end

show{T}(io::IO, x::LoadCmd{T}) = (print(io,"0x",hex(x.off,8),":\n "); show(io,x.cmd); print(io,'\n'))
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
children(h::MachOHandle) = LoadCmds(h)

# A tuple of the position before the current load command,
# the number of the load command and the size of the current load
# command. I.e. the next load command will be found at state[1]+state[3]
start(l::LoadCmds) = (l.start,0,0)
seek(l::LoadCmds,state) = seek(l.h,state[1]+state[3])
function next(l::LoadCmds,state)
    seek(l,state)
    cmdh,cmd = readloadcmd(l.h)
    (LoadCmd(l.h,state[1]+state[3],cmdh.cmd,cmd),(state[1]+state[3],state[2]+1,cmdh.cmdsize))
end
length(l::LoadCmds) = l.ncmds
done(l::LoadCmds,state) = state[2] >= length(l)

# Access to sections

const segment_commands = Union{segment_command_64,segment_command}

immutable Sections <: ObjFileBase.Sections{MachOHandle}
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
ObjFileBase.handle(sects::Sections) = sects.h
ObjFileBase.Sections(segment::LoadCmd) = Sections(segment)
ObjFileBase.Sections(h::MachOHandle, args...) = Sections(h,args...)
ObjFileBase.mangle_sname(h::MachOHandle, name) = string("__", name)

# Covenience function for the (common) case where the object
# only has one segment
function Sections(h::MachOHandle)
    seglcs = collect(filter(LoadCmds(h)) do lc
        isa(lc.cmd, segment_commands)
    end)
    # @assert length(seglcs) == 1
    Sections(seglcs[])
end

immutable SectionRef{H<:MachOHandle, T<:Union{section,section_64}} <: ObjFileBase.SectionRef{MachOHandle}
    handle::MachOHandle
    header::T
end
@Base.pure ObjFileBase.SectionRef{H<:MachOHandle}(::Type{H}) = SectionRef{H}
deref(x::SectionRef) = x.header
handle(x::SectionRef) = x.handle
sectionname(x::SectionRef) = sectionname(deref(x))
sectionaddress(x::SectionRef) = sectionaddress(deref(x))

length(s::Sections) = s.command.nsects
function getindex(s::Sections,n)
    if n < 1 || n > length(s)
        throw(BoundsError())
    end
    sT = isa(s.command,segment_command_64) ? section_64 : section
    seek(s.h,s.start + (n-1)*sizeof(sT))
    SectionRef{typeof(s.h),sT}(s.h,unpack(s.h, sT))
end

start(s::Sections) = 1
done(s::Sections,n) = n > length(s)
next(s::Sections,n) = (s[n],n+1)


for f in (:readuntil,:write)
    @eval $(f){T<:IO}(io::MachOHandle{T},args...) = $(f)(io.io,args...)
end
read{T<:IO}(io::MachOHandle{T},num::Integer) = read(io.io,num)


seek{T<:IO}(io::MachOHandle{T},pos::Integer) = seek(io.io,io.start+pos)
seekstart(io::MachOHandle) = seek(io.io,io.start)
position{T<:IO}(io::MachOHandle{T}) = position(io.io)-io.start

unpack{T,ioT<:IO}(h::MachOHandle{ioT},::Type{T}) =
    unpack(h.io,T,h.bswapped ? :SwappedEndian : :NativeEndian)

# Access to relocations
immutable Relocations
    sec::SectionRef
end

immutable RelocationRef <: ObjFileBase.RelocationRef{MachOHandle}
    h::MachOHandle
    reloc::relocation_info
end

deref(x::RelocationRef) = x.reloc

entrysize(s::Relocations) = sizeof(relocation_info)
endof(s::Relocations) = s.sec.header.nreloc
length(r::Relocations) = endof(r)
function getindex(s::Relocations,n)
    if n < 1 || n > length(s)
        throw(BoundsError())
    end
    offset = s.sec.header.reloff +
        (n-1)*entrysize(s)
    seek(s.sec.handle,offset)
    RelocationRef(s.sec.handle,unpack(s.sec.handle, relocation_info))
end


start(s::Relocations) = 1
done(s::Relocations,n) = n > length(s)
next(s::Relocations,n) = (x=s[n];(x,n+1))


function unpack{ioT<:IO}(h::MachOHandle{ioT}, ::Type{UInt32})
    return unpack(h.io, UInt32, endianness(h))
end

pack{T,ioT<:IO}(h::MachOHandle{ioT},::Type{T}) =
    pack(h.io,T,h.bswapped ? :SwappedEndian : :NativeEndian)

function readheader(h::MachOHandle)
    seekstart(h)
    unpack(h,h.is64 ? mach_header_64 : mach_header)
end

ObjFileBase.isrelocatable(handle::MachOHandle) =
    readheader(handle).filetype == MachO.MH_OBJECT

sectionsize(sect::Union{section,section_64}) = sect.size
# In non-relocatable files, address and offset are the same and offset is 0
sectionoffset(sect::Union{section,section_64}) = sect.offset == 0 ? sect.addr : sect.offset

### Access to Symbols

immutable Symbols <: ObjFileBase.Symbols{MachOHandle}
    lc::LoadCmd{symtab_command}
end
ObjFileBase.Symbols(lc::LoadCmd) = Symbols(lc)
ObjFileBase.Symbols(h::MachOHandle) = Symbols(h)
symname(syms::Symbols, sym) = symname(syms.lc, sym)
ObjFileBase.StrTab(s::Symbols) = ObjFileBase.StrTab(s.lc)

immutable SymbolRef <: ObjFileBase.SymbolRef{MachOHandle}
    symbols::Symbols
    num::UInt32
    entry::ObjFileBase.SymtabEntry{MachOHandle}
end
deref(x::SymbolRef) = x.entry
symbolnum(x::SymbolRef) = x.num
symbolvalue(x::SymbolRef, args...) = deref(x).n_value
handle(x::SymbolRef) = x.handle

isglobal(x) = (x.n_type & N_EXT) != 0
islocal(x) = !isglobal(x) && ((x.n_type & N_UNDF) == 0)
isweak(x) = (x.n_desc & (N_WEAK_REF | N_WEAK_DEF)) != 0
isdebug(x) = (x.n_type & N_TYPE) == N_STAB
isundef(x::ObjFileBase.SymtabEntry{MachOHandle}) = (x.n_type == N_UNDF) || ((x.n_type & N_EXT) != 0 && (x.n_sect == NO_SECT))

# Symbol printing stuff
function showcompact(io::IO, x::SymbolRef)
    print(io,'[')
    printfield(io,dec(symbolnum(x)),5)
    print(io,"] ")
    showcompact(io, x.entry; syms = x.symbols, sections = Sections(handle(x.symbols.lc)))
end

# Try to follow the same format as llvm-objdump
function showcompact(io::IO,x::ObjFileBase.SymtabEntry{MachOHandle};
        syms = nothing, sections = nothing)
    # Value
    print(io,string("0x",hex(x.n_value,2*sizeof(x.n_value))))
    print(io," ")

    # Symbol flags
    print(io, isglobal(x) ? "g" : islocal(x) ? "l" : "-")
    print(io, isweak(x) ? "w" : "-")
    print(io, "-"^3) # Unsupported
    print(io, isdebug(x) ? "d" : "-")

    # Skip Symbol type (TODO)
    print(io, " ")

    print(io, " ")
    if (x.n_type & N_TYPE) == N_UNDF && isglobal(x)
            printfield(io,
                x.n_value != 0 ? "*COM*" : "*UND*",
                20; align = :left)
    elseif (x.n_type & N_TYPE) == N_ABS
        printfield(io,"*ABS*",20; align = :left)
    elseif sections !== nothing
        printfield(io, sectionname(sections[x.n_sect]), 20; align = :left)
    else
        printfield(io, "Section #$(x.n_sect)", 20; align = :left)
    end
    print(io, " ")

    if syms !== nothing
        print(io,symname(syms, x))
    else
        print(io,"@",x.n_strx)
    end
end

function Symbols(oh::MachOHandle)
    symlcs = [lc for lc in LoadCmds(oh) if isa(lc.cmd, symtab_command)]
    @assert length(symlcs) == 1
    return Symbols(symlcs[1])
end

start(s::Symbols) = 1
done(s::Symbols,n) = n > length(s)
next(s::Symbols,n) = (s[n],n+1)

length(s::Symbols) = s.lc.cmd.nsyms
function getindex(s::Symbols,n)
    if n < 1 || n > length(s)
        throw(BoundsError())
    end
    sT = s.lc.h.is64 ? nlist_64 : nlist
    seek(s.lc.h,s.lc.cmd.symoff + (n-1)*sizeof(sT))
    SymbolRef(s, n-1, unpack(s.lc.h, sT))
end

immutable SectionStrTab <: ObjFileBase.StrTab
    strtab::SectionRef
end
immutable OffsetStrTab <: ObjFileBase.StrTab
    h::MachOHandle
    offset::UInt
    size::UInt
end
ObjFileBase.StrTab(s::SectionRef) = SectionStrTab(s)
ObjFileBase.StrTab(s::LoadCmd{symtab_command}) =
    OffsetStrTab(handle(s),deref(s).stroff,deref(s).strsize)

function strtab_lookup(s::SectionStrTab,index)
    seek(s.strtab.handle,sectionoffset(s.strtab)+index)
    strip(readuntil(s.strtab.handle,'\0'),'\0')
end
function strtab_lookup(s::OffsetStrTab,index)
    @assert index < s.size
    seek(s.h,s.offset+index)
    strip(readuntil(s.h,'\0'),'\0')
end
load_strtab(strtab::SectionRef) = SectionStrTab(strtab)

function strtable_lookup(io::MachOHandle,command::symtab_command,offset)
    seek(io,command.stroff+offset)
    strip(readuntil(io,'\0'),'\0')
end

symname(io::MachOHandle,command::symtab_command,sym) = strtable_lookup(io, command, sym.n_strx)
symname(sym::SymbolRef; strtab = ObjFileBase.StrTab(sym.symbols), kwargs...) = strtab_lookup(strtab, deref(sym).n_strx)
symname(x::LoadCmd{symtab_command}, sym) = symname(x.h, x.cmd, sym)
segname(x::Union{segment_command_64,section_64}) = x.segname
segname(x::LoadCmd{segment_command_64}) = segname(x.cmd)
sectionname(x::section_64) = x.sectname
sectionaddress(x::section_64) = x.addr

### Fat Handle
immutable FatMachOHandle
    io::IO
    start::UInt64
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

function show(io::IO,h::fat_arch)
    printentry(io,"cputype",CPUTYPES[h.cputype])
    # TODO: subtype printing
    #printentry(io,"cputype",CPUSUBTYPES[h.cputype])
    printentry(io,"offset","0x",hex(h.offset,2sizeof(UInt32)))
    printentry(io,"size","0x",hex(h.size,2sizeof(UInt32)))
    printentry(io,"align",dec(h.align))
end

function show(io::IO,h::FatMachOHandle)
    print(io, "Fat Mach Handle (",length(h.archs), " architectures)")
    for (i,arch) in enumerate(h.archs)
        println(io)
        println(io, "architecture ", i)
        print(io, arch)
    end
end

function getindex(h::FatMachOHandle,i)
    seek(h.io,h.start + h.archs[i].offset)
    readmeta(h.io,MachOHandle)
end

### Compact Unwind Support

include("compact_unwind.jl")

### Relocation Support

include("relocate.jl")

### DWARF support

function debugsections{T<:segment_commands}(seg::LoadCmd{T})
    sects = collect(Sections(seg))
    snames = map(sectionname,sects)
    sections = Dict{String,SectionRef}()
    for i in 1:length(snames)
        # remove leading "__"
        ind = findfirst(ObjFileBase.DEBUG_SECTIONS,unsafe_string(snames[i])[3:end])
        if ind != 0
            sections[ObjFileBase.DEBUG_SECTIONS[ind]] = sects[i]
        end
    end
    sections
end

function debugsections(oh::MachOHandle)
    segs = collect(filter(LoadCmds(oh)) do lc
        isa(lc.cmd, segment_commands) &&
            (segname(lc) == "__DWARF" || isempty(segname(lc)))
    end)
    isempty(segs) && error("No debug sections present")
    @assert length(segs) == 1
    ObjFileBase.DebugSections(oh,debugsections(first(segs)))
end

include("precompile.jl")

end # module
