# Compact unwind data structure

@struct immutable unwind_info_section_header
    version::Uint32
    commonEncodingsArraySectionOffset::Uint32
    commonEncodingsArrayCount::Uint32
    personalityArraySectionOffset::Uint32
    personalityArrayCount::Uint32
    indexSectionOffset::Uint32
    indexCount::Uint32
end

function show(io::IO,h::unwind_info_section_header)
    println(io,"Unwind Info Section Header:")

    printentry(io,"version",h.version)
    printentry(io,"CEAoffset","0x",hex(h.commonEncodingsArraySectionOffset,2*sizeof(Uint32)))
    printentry(io,"CEACount",h.commonEncodingsArrayCount)
    printentry(io,"persOffset","0x",hex(h.personalityArraySectionOffset,2*sizeof(Uint32)))
    printentry(io,"persCount",h.personalityArrayCount)
    printentry(io,"indexOffset","0x",hex(h.indexSectionOffset,2*sizeof(Uint32)))
    printentry(io,"indexCount",h.indexCount)
end


@struct immutable unwind_info_section_header_index_entry
    functionOffset::Uint32
    secondLevelPagesSectionOffset::Uint32
    lsdaIndexArraySectionOffset::Uint32
end

function show(io::IO,h::unwind_info_section_header_index_entry)
    println(io,"Unwind Info Section Header:")

    printentry(io,"functionOffset","0x",hex(h.functionOffset,2*sizeof(Uint32)))
    printentry(io,"secondLevelOff","0x",hex(h.secondLevelPagesSectionOffset,2*sizeof(Uint32)))
    printentry(io,"lsdaIndexOffset","0x",hex(h.lsdaIndexArraySectionOffset,2*sizeof(Uint32)))
end


@struct immutable unwind_info_section_header_lsda_index_entry
    functionOffset::Uint32
    lsdaOffset::Uint32
end

@struct immutable unwind_info_regular_second_level_page_header
    entryPageOffset::Uint16
    entryCount::Uint16
end

@struct immutable unwind_info_compressed_second_level_page_header
    entryPageOff::Uint16
    entryCount::Uint16
    encodingsPageOffset::Uint16
    encodingsCount::Uint16
end

function show(io::IO,h::unwind_info_compressed_second_level_page_header)
    println(io,"Compressed Second Level Page:")

    printentry(io,"entryPageOff","0x",hex(h.entryPageOff,2*sizeof(Uint16)))
    printentry(io,"entryCount",h.entryCount)
    printentry(io,"encPageOff","0x",hex(h.encodingsPageOffset,2*sizeof(Uint16)))
    printentry(io,"encCount",h.encodingsCount)
end

function readSecondLevelHeader(io::IO)
    kind = read(io,Uint32)
    if kind == UNWIND_SECOND_LEVEL_REGULAR
        return unpack(io,unwind_info_regular_second_level_page_header)
    elseif kind == UNWIND_SECOND_LEVEL_COMPRESSED
        return unpack(io,unwind_info_compressed_second_level_page_header)
    else
        error("Unrecognized second level page header")
    end
end

function findEntry(io::IO, off)
    header = unpack(io,unwind_info_section_header)
    if header.indexCount == 0
        error("Unwind section is empty")
    end
    seek(io,header.indexSectionOffset)
    idxs = [unpack(io,unwind_info_section_header_index_entry) for _=1:header.indexCount]
    local idx
    for i = 1:header.indexCount
        if i == header.indexCount || idxs[i].functionOffset <= off <= idxs[i+1].functionOffset
            idx = i
            break
        end
    end
    if idxs[idx].functionOffset > off
        error("How could this happen?")
    end
    seek(io,idxs[idx].secondLevelPagesSectionOffset)
    slh = readSecondLevelHeader(io)
    if isa(slh, unwind_info_compressed_second_level_page_header)
        seek(io,idxs[idx].secondLevelPagesSectionOffset+slh.entryPageOff)
        entries = read!(io,Array(Uint32,slh.entryCount))
        for i = 1:slh.entryCount
            if i == slh.entryCount || (entries[i] & 0x00FFFFFF) <= off <= (entries[i+1] & 0x00FFFFFF)
                return entries[i]
            end
        end
        error("Entry not found")
    else
        error("Unimplemented")
    end
end