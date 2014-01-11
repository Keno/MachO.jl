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

export readmeta, readheader, LoadCmds, Sections

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


############################ Data Structures ###################################
#
# This section contains data structures as defined by the MachO specification.
# They are used below to acutally read in the data and may be ocassionally 
# referenced from interface structs where this is convenient and no other 
# interface exists
#
################################################################################

#

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

@struct immutable uuid_command
    uuid::Uint128
end

# A 16 byte string, represented as a Uint128, but shown as a string
@struct immutable small_fixed_string
    string::Uint128
end

@struct immutable segment_command
    shename::small_fixed_string
    vmaddr::Uint32
    vmsize::Uint32
    fileoff::Uint32
    filesize::Uint32
    maxprot::Uint32
    initprot::Uint32
    nsects::Uint32
    flags::Uint32
end

@struct immutable segment_command_64
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

@struct immutable section
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

@struct immutable section_64
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

@struct immutable symtab_command
    symoff::Uint32
    nsyms::Uint32
    stroff::Uint32
    strsize::Uint32
end

@struct immutable dysymtab_command
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


########################### Printing Data Structures ###########################
#
# This prints the basic Mach-O data structures above. Where there is no good 
# reason not to, the output matches that of otool.
#
################################################################################

import Base: show, print, bytestring

function bytestring(x::small_fixed_string)
    a8 = reinterpret(Uint8,[x.string])
    z = findfirst(a8,0)
    ASCIIString(a8[1:(z == 0 ? length(a8) : z-1)])
end
print(io::IO,x::small_fixed_string) = print(io,bytestring(x))

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
    println("Load Command (",isa(l,segment_command_64)?"SEGMENT_64":
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
    println("  Section:")

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
    println("Load Command (SYMTAB):")
    printentry(io,"symoff",dec(l.symoff))
    printentry(io,"nsyms",dec(l.nsyms))
    printentry(io,"stroff",dec(l.stroff))
    printentry(io,"strsize",dec(l.strsize))
end

function show(io::IO,l::dysymtab_command)
    println("Load Command (DYSYMTAB):")
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

################################ Interface #####################################

import Base: show,
    # IO methods
    read, write, seek, seekstart, position,
    # Iteration
    start, next, done,
    # Indexing
    length, getindex

import StrPack: unpack, pack

#
# Represents the actual MachO file
#
immutable MachOHandle{T<:IO}
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

MachOHandle{T<:IO}(io::T,start::Int,bswapped::Bool,is64::Bool) = 
    MachOHandle{T}(io,start,bswapped,is64)

function show(io::IO,h::MachOHandle)
    print(io,"MachO handle (")
    print(io,h.is64?"64-bit":"32-bit")
    h.bswapped && print(io,",swapped")
    print(io,")")
end

#
# The main entry point for MachO.jl (see ELF.jl for comparison). Constructs
# and initializes the MachOHandle object
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
    else 
        error("Invalid Magic!")
    end
end

function readloadcmd(h::MachOHandle)
    cmd = unpack(h,load_command)
    if cmd.cmd == LC_UUID
        return (cmd,unpack(h, uuid_command))
    elseif cmd.cmd == LC_SEGMENT
        return (cmd,unpack(h, segment_command))
    elseif cmd.cmd == LC_SEGMENT_64
        return (cmd,unpack(h, segment_command_64))
    elseif cmd.cmd == LC_SYMTAB
        return (cmd,unpack(h, symtab_command))
    elseif cmd.cmd == LC_DYSYMTAB
        return (cmd,unpack(h, dysymtab_command))
    else
        error("Unimplemented load command $(cmd.cmd)")
    end
end

## Iteration

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
function next(l::LoadCmds,state)
    seek(l.h,state[1]+state[3])
    cmdh,cmd = readloadcmd(l.h)
    (cmd,(state[1]+state[3],state[2]+1,cmdh.cmdsize))
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


read{T<:IO}(io::MachOHandle{T},args...) = read(io.io,args...)
write{T<:IO}(io::MachOHandle{T},args...) = write(io.io,args...)
seek{T<:IO}(io::MachOHandle{T},pos) = seek(io.io,io.start+pos)
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

end # module
