using Base.Test
using MachO

@testset "library" begin
    # First, load in libfoo.dylib
    h = readmeta("./libfoo.dylib")

    # Assert some basic properties of this image
    @test h.is64
    @test !h.bswapped

    # Inspect the load commands.  We know what this file contains, and so we
    # can assert certain things about the load commands, etc...
    load_cmds = collect(LoadCmds(h))
    @test length(load_cmds) == 12
    @test load_cmds[1].cmd_id == MachO.LC_SEGMENT_64

    # Look at all the dylibs we will try to load
    dylibs = [c.cmd.name for c in load_cmds if c.cmd_id == MachO.LC_LOAD_DYLIB]
    @test length(dylibs) == 1
    @test "/usr/lib/libSystem.B.dylib" in dylibs
end

@testset "executable" begin
    h = readmeta("./fooifier")
    @test h.is64
    @test !h.bswapped

    load_cmds = collect(LoadCmds(h))
    @test length(load_cmds) == 18
    @test load_cmds[1].cmd_id == MachO.LC_SEGMENT_64

    dylibs = [c.cmd.name for c in load_cmds if c.cmd_id == MachO.LC_LOAD_DYLIB]
    @test length(dylibs) == 2
    @test "/usr/lib/libSystem.B.dylib" in dylibs
    @test "@rpath/libfoo.dylib" in dylibs

    # Inspect symbols
    symbols = collect(MachO.Symbols(h))
    symbol_names = [MachO.symname(s) for s in symbols]

    # Check that _main is a symbol and is defined
    main_idx = get(find(symbol_names .==  "_main"), 1, 0)
    @test main_idx > 0
    @test !MachO.isundef(MachO.deref(symbols[main_idx]))

    # Check that _foo is a symbol and is not defined
    foo_idx = get(find(symbol_names .==  "_foo"), 1, 0)
    @test foo_idx > 0
    @test MachO.isundef(MachO.deref(symbols[foo_idx]))
end