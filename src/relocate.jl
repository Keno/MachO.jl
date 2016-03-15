import ObjFileBase: getSectionLoadAddress

r_symbolnum(r::relocation_info) = r.target & 0xFFFFFF
r_pcrel(r::relocation_info) = ((r.target & (1<<24)) >> 24) != 0
r_length(r::relocation_info) = (r.target & (UInt32(0b11) << 25)) >> 25
r_extern(r::relocation_info) = ((r.target & (1 << 27)) >> 27) != 0
r_type(r::relocation_info) = (r.target & (1 << 28)) >> 28
for f in (:r_symbolnum, :r_pcrel, :r_length, :r_extern, :r_type)
    @eval ($f)(r::RelocationRef) = ($f)(deref(r))
end

# The relocation to apply
immutable RelocToApply
    value::UInt64
    size::UInt8
end

function compute_value(h, symbols, sections, LOI, reloc)
    # Here one could to external symbol lookups, etc, but I'm not interested
    reloc = deref(reloc)
    if r_extern(reloc)
        symbols[r_symbolnum(reloc)]
    else
        @assert LOI !== nothing
        sections[r_symbolnum(reloc)]
    end
end

# Apply relocations in `buffer`. `h` should be the buffer being relocated
function relocate!(buffer, h; LOI = nothing, debug_only = true)
    scs = filter(LoadCmds(h)) do lc
        isa(lc.cmd, segment_commands)
    end
    symbols = Symbols(first(filter(LoadCmds(h)) do lc
        isa(lc.cmd, symtab_command)
    end))
    header = readheader(h)
    for lc in scs
        sects = Sections(lc)
        for sec in sects
            if debug_only && deref(sec).segname != "__DWARF"
                continue
            end
            for reloc in Relocations(sec)
              Value = compute_value(h, symbols, sects, LOI, reloc)
              Value = getSectionLoadAddress(LOI, Value) - deref(Value).addr
              rta = compute_relocation(header, reloc, Value)
              seek(buffer, sectionoffset(sec) + deref(reloc).address)
              write(buffer, rta.size == 8 ? rta.value :
                  rta.size == 4 ? convert(UInt32,rta.value) :
                  rta.size == 2 ? convert(UInt16,rta.value) :
                  rta.size == 1 ? convert(UInt8,rta.value) :
                  error("Unsupported Relocation Size"))
            end
        end
    end
end

function compute_relocation(header, reloc, Value)
    if header.cputype == CPU_TYPE_X86_64
        compute_X86_64(reloc, Value)
    end
end

function compute_X86_64(reloc, Value)
    if r_type(deref(reloc)) == X86_64_RELOC_UNSIGNED
        RelocToApply(Value, 1 << r_length(reloc))
    else
        error("Unknown Relocation $(X86_64_RELOC[r_type(deref(reloc))])")
    end
end

function relocateByLOI!(buffer, h, LOI)
    scs = filter(LoadCmds(h)) do lc
        isa(lc.cmd, segment_commands)
    end
    for lc in scs
      sects = Sections(lc)
      for sec in sects
          addr = try
              getSectionLoadAddress(LOI, sec)
          catch
              continue
          end
          ssize = sectionsize(sec)
          seek(buffer, sectionoffset(sec))
          write(buffer, pointer_to_array(
            reinterpret(Ptr{UInt8}, addr), (ssize,), false))
      end
    end
end
