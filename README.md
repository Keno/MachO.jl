# MachO

[![Build Status](https://travis-ci.org/Keno/MachO.jl.png)](https://travis-ci.org/Keno/MachO.jl)


# Usage

MachO.jl implements the ObjFileBase interface.

To open a MachO file simply:
```julia
julia> using MachO
julia> # NOTE: ObjFileBase.readmeta is reexported by MachO
julia> h = readmeta("/usr/lib/libz.a")
Fat Mach Handle (2 architectures)
architecture 1
        cputype X86_64
         offset 0x00001000
           size 0x00015710
          align 12

architecture 2
        cputype X86
         offset 0x00017000
           size 0x000125b0
          align 12
```

This will return a handle to the MachO object file. If your object file contains MachO headers for multiple
architectures (like in the example above). Simply index into the handle
to obtain a handle for the MachO object:

```julia
julia> mh = h[1]
MachO handle (64-bit)
```

# Accessing Load Commands
Load commands are accessed via the iteration protocol using the iterator
`LoadCmds`. The easiest way to see all the load sections in a file is to use
`collect`:
```
julia> collect(LoadCmds(h[1]))
16-element Array{Any,1}:
 0x00000020:
 Load Command (SEGMENT_64):
           name __TEXT
           addr 0
           size 73728
        fileoff 0
       filesize 73728
        maxprot rwx
       initprot rx
         nsects 6
          flags (none)
[snip]
```

# Working with load commands

Note that the object returned by the iterator is not the load command itself, but an object also containing a reference to the object file.
This is done for convenice as it prevents the need to pass the object file around at the command line.

# Accessing the symbols in a segment

As with load commands, symbols are accessed via an iterator interface,
however instead of passing the object handle into the iterator, it expects
a load section denoting a symbol table:

```
julia> l = filter(x->eltype(x)==MachO.symtab_command,LoadCmds(mh)) |> first
0x000004c8:
 Load Command (SYMTAB):
         symoff 79552
          nsyms 87
         stroff 81104
        strsize 1056

julia> Symbols(l) |> collect
87-element Array{Any,1}:
 nlist_64(0x00000407,0x3c,0x00,0x0000,0x0000000005614542)
 nlist_64(0x00000004,0x0f,0x01,0x0000,0x00000000000010f0)
 nlist_64(0x0000000d,0x0f,0x01,0x0000,0x0000000000001218)
[snip]
```

# Finding symbols by name
The `symname` functions can be used to get the name of a symbol:

```
julia> map(x->symname(l,x),Symbols(l))
87-element Array{Any,1}:
 "radr://5614542"
 "_adler32"
 "_adler32_combine"
 "_compress"

julia> filter(x->symname(l,x)=="_compress",Symbols(l)) |> first
nlist_64(0x0000001e,0x0f,0x01,0x0000,0x00000000000013a3)
```
