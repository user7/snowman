#include "LeParser.h"
#include <nc/core/input/ParseError.h>
#include <nc/core/input/Utils.h>
#include <nc/core/image/Section.h>
#include <nc/core/image/Image.h>
#include <nc/core/image/Relocation.h>
#include <nc/common/make_unique.h>
#include <nc/common/LogToken.h>
#include <nc/common/ByteOrder.h>
#include <nc/common/Foreach.h>

namespace nc {
namespace input {
namespace le {

namespace {

struct header_pos {
    long mz;
    long le;
};

using nc::core::input::read;
using nc::core::input::ParseError;

const ByteOrder bo = ByteOrder::LittleEndian;

header_pos find_header_pos(QIODevice *in) {
    char a;
    while (in->getChar(&a)) {
    again:
        if (a != 'M')
            continue;
        char b;
        if (!in->getChar(&b))
            break;
        if (b != 'Z') {
            a = b;
            goto again;
        }
        long mz = in->pos() - 2;
        if (!in->seek(mz + 0x3c))
            break;
        uint32_t le_off;
        if (!read(in, le_off))
            break;
        bo.convertFrom(le_off);
        if (!in->seek(mz + le_off))
        {
        rewind:
            in->seek(mz + 2);
            continue;
        }
        char le_sig[2];
        if (!read(in, le_sig))
            goto rewind;
        if (memcmp(le_sig, "LE", 2))
            goto rewind;
        header_pos hpos = { .mz = mz, .le = mz + le_off };
        return hpos;
    }
    return { -1, -1 };
}

#define LE_HEADER \
    FIELD(uint16_t, signature) \
    FIELD(uint8_t,  byte_order) \
    FIELD(uint8_t,  word_order) \
    FIELD(uint32_t, unused) \
    FIELD(uint16_t, cpu) \
    FIELD(uint16_t, os) \
    FIELD(uint32_t, unused2) \
    FIELD(uint32_t, unused3) \
    FIELD(uint32_t, pages) \
    FIELD(uint32_t, initial_object_CS_number) \
    FIELD(uint32_t, initial_EIP) \
    FIELD(uint32_t, initial_object_SS_number) \
    FIELD(uint32_t, initial_ESP) \
    FIELD(uint32_t, memory_page_size) \
    FIELD(uint32_t, bytes_on_last_page) \
    FIELD(uint32_t, fixup_section_size) \
    FIELD(uint32_t, fixup_section_checksum) \
    FIELD(uint32_t, loader_section_size) \
    FIELD(uint32_t, loader_section_checksum) \
    FIELD(uint32_t, offset_of_object_table) \
    FIELD(uint32_t, object_table_entries) \
    FIELD(uint32_t, object_page_map_offset) \
    FIELD(uint32_t, object_iterate_data_map_offset) \
    FIELD(uint32_t, resource_table_offset) \
    FIELD(uint32_t, resource_table_entries) \
    FIELD(uint32_t, resident_names_table_offset) \
    FIELD(uint32_t, entry_table_offset) \
    FIELD(uint32_t, module_directive_table_offset) \
    FIELD(uint32_t, module_directive_entries) \
    FIELD(uint32_t, fixup_page_table_offset) \
    FIELD(uint32_t, fixup_record_table_offset) \
    FIELD(uint32_t, imported_modules_name_table_offset) \
    FIELD(uint32_t, inported_modules_count) \
    FIELD(uint32_t, imported_procedure_name_table_offset) \
    FIELD(uint32_t, per_page_checksum_table_offset) \
    FIELD(uint32_t, data_pages_offset_from_top_of_file) \

enum {
    OBJECT_READABLE     = 1 << 0,
    OBJECT_WRITABLE     = 1 << 1,
    OBJECT_EXECUTABLE   = 1 << 2,
    OBJECT_DISCARDABLE  = 1 << 4,
};

#define OBJ_HEADER \
    FIELD(uint32_t, virtual_segment_size) \
    FIELD(uint32_t, relocation_base_address) \
    FIELD(uint32_t, object_flags) \
    FIELD(uint32_t, page_map_index) \
    FIELD(uint32_t, page_map_entries) \
    FIELD(uint32_t, unused) \

#define FIXUP_HEADER \
    FIELD(uint8_t, src) \
    FIELD(uint8_t, flags) \
    FIELD(int16_t, srcoff) \
    FIELD(uint8_t, object) \

#define EMIT_ALL \
    EMIT(LE_HEADER, le_header) \
    EMIT(OBJ_HEADER, obj_header) \
    EMIT(FIXUP_HEADER, fixup_header) \

// emitting structs
#define EMIT(fields, name) struct name { fields } __attribute__((packed));
#define FIELD(t, n) t n;
EMIT_ALL
#undef FIELD
#undef EMIT

// -----------------------------------------------------------------------------
#define EMIT(fields, name) void fix_byte_order(name &h) { fields }
#define FIELD(t, n) bo.convert(&h.n, sizeof(h.n), bo, ByteOrder::Current);
EMIT_ALL
#undef FIELD
#undef EMIT

template <typename T>
void fix_byte_order(T &v) {
    bo.convertFrom(v);
}

// -----------------------------------------------------------------------------

#define EMIT(fields, name) \
QString toQString(const name &h) __attribute__((unused)); \
QString toQString(const name &h) { \
    QString s = QString::fromLatin1(#name ":"); \
    fields \
    return s; \
}
#define FIELD(t, n) s.append(QString::fromLatin1("\n" #n " %1").arg(h.n, 1, 16));
EMIT_ALL
#undef EMIT
#undef FIELD

// -----------------------------------------------------------------------------

template <typename V, typename E>
void checked_read(QIODevice *in, V &val, const E &err) {
    if (!read(in, val))
        err();
    fix_byte_order(val);
}

} // namespace

LeParser::LeParser():
    core::input::Parser(QLatin1String("LE"))
{}

bool LeParser::doCanParse(QIODevice *in) const {
    return find_header_pos(in).le != -1;
}

void LeParser::doParse(QIODevice *in, core::image::Image *image, const LogToken &log) const {
    header_pos hpos = find_header_pos(in);
    le_header h;
    if (!in->seek(hpos.le) || !read(in, h)) {
        throw ParseError(tr("Truncated LE header"));
    }
    if (h.byte_order) {
        throw ParseError(tr("Big endian byte order in LE is unsupported"));
    }
    if (h.word_order) {
        throw ParseError(tr("Big endian word order in LE is unsupported"));
    }
    fix_byte_order(h);
    log.debug(toQString(h));

    image->platform().setArchitecture(QLatin1String("i386"));
    image->platform().setOperatingSystem(core::image::Platform::DOS);

    // = loading sections =

    std::vector<obj_header> sec_headers;
    for (uint32_t oi = 0; oi < h.object_table_entries; ++oi) {
        long pos = hpos.le + h.offset_of_object_table + 24 * oi;
        obj_header oh;
        if (!in->seek(pos) || !read(in, oh)) {
            throw ParseError(tr("Truncated object entry %1").arg(oi));
        }
        fix_byte_order(oh);
        sec_headers.push_back(oh);
        auto section = std::make_unique<core::image::Section>(
                            QString(QLatin1String(".seg%1")).arg(oi),
                            long(oh.relocation_base_address),
                            long(oh.page_map_entries * h.memory_page_size));
        section->setAllocated((oh.object_flags & OBJECT_DISCARDABLE) == 0);
        section->setReadable(oh.object_flags & OBJECT_READABLE);
        section->setWritable(oh.object_flags & OBJECT_WRITABLE);
        if (oh.object_flags & OBJECT_EXECUTABLE) {
            section->setExecutable(true);
            section->setCode(true);
        } else {
            section->setData(true);
        }
        long off = hpos.mz + h.data_pages_offset_from_top_of_file + (oh.page_map_index - 1) * h.memory_page_size;
        long len = oh.page_map_entries * h.memory_page_size;
        QByteArray bytes;
        if (!in->seek(off) || (bytes = in->read(len), bytes.size() != len)) {
            throw ParseError(tr("Truncated object body at 0x%1:0x%2 for object %3").arg(off, 1, 16).arg(len, 1, 16).arg(oi));
        }
        section->setContent(std::move(bytes));
        log.debug(tr("Adding section %1 at 0x%2:0x%3").arg(section->name()).arg(off, 1, 16).arg(len, 1, 16));
        image->addSection(std::move(section));
        if (h.initial_object_CS_number - 1 == oi) {
            image->setEntryPoint(oh.relocation_base_address + h.initial_EIP);
            log.debug(tr("Entry point set to 0x%1").arg(oh.relocation_base_address + h.initial_EIP, 1, 16));
        }

        core::image::Section *s = image->sections()[oi];
        image->addSymbol(std::make_unique<core::image::Symbol>(core::image::SymbolType::NOTYPE, s->name(), long(oh.relocation_base_address), s));
    }

    // TODO parseSymbols();
    // TODO parseImports();

    // = loading fixups =

    long fpt_off = hpos.le + h.fixup_page_table_offset;
    std::vector<uint32_t> fixup_page_table(h.pages + 1);
    long fpt_size = fixup_page_table.size() * 4;
    if (!in->seek(fpt_off) || in->read((char *) &fixup_page_table[0], fpt_size) != fpt_size) {
        throw ParseError(tr("Truncated fixup page table at 0x%1:0x%2").arg(fpt_off, 1, 16).arg(fpt_size, 1, 16));
    }
    foreach(auto &s, fixup_page_table) {
        bo.convertFrom(s);
    }

    for (long npage = 0; npage < h.pages; ++npage) {
        long start = hpos.le + h.fixup_record_table_offset + fixup_page_table[npage];
        long end = hpos.le + h.fixup_record_table_offset + fixup_page_table[npage + 1];
        if (!in->seek(start)) {
            throw ParseError(tr("Truncated fixup block for page %1 at 0x%2").arg(npage).arg(start, 1, 16));
        }

        uint32_t seci;
        for (seci = 0; seci < sec_headers.size(); ++seci) {
            long b = sec_headers[seci].page_map_index - 1, e = b +  sec_headers[seci].page_map_entries;
            if (npage >= b && npage < e)
                break;
        }
        if (seci == sec_headers.size()) {
            throw ParseError(tr("No section corresponds to page %1").arg(npage));
        }
        long page_virt_addr = image->sections()[seci]->addr() + (npage + 1 - sec_headers[seci].page_map_index) * h.memory_page_size;

        while (start + 5 <= end) {
            long start_mark = start;
            auto throw_truncated = [npage, start]() {
                throw ParseError(tr("Truncated fixup for page %1 at 0x%2").arg(npage).arg(start, 1, 16));
            };
            fixup_header fh;
            checked_read(in, fh, throw_truncated);
            if (fh.src == 2) {
                start += 5; // TODO ds word relocation
                continue;
            }
            if (fh.src != 7) {
                throw ParseError(tr("Fixup at 0x%1 has unsupported src %2").arg(start_mark, 1, 16).arg(fh.src));
            }
            uint32_t dst;
            if (fh.flags == 0x10) {
                checked_read(in, dst, throw_truncated);
                start += 9;
            } else if (fh.flags == 0) {
                uint16_t dst16;
                checked_read(in, dst16, throw_truncated);
                dst = dst16;
                start += 7;
            } else {
                throw ParseError(tr("Fixup at 0x%1 has unsupported flags 0x%2").arg(start_mark, 1, 16).arg(fh.flags, 1, 16));
            }

            // skipping fixups that cross page lower boundary, they're accounted for by the previous page
            if (fh.srcoff < 0) {
                continue;
            }

            long reloc_at = page_virt_addr + fh.srcoff;
            if (fh.object > sec_headers.size()) {
                throw ParseError(tr("Fixup at 0x%1 mentions object %2, but binary has only %3 objects")
                                    .arg(start_mark, 1, 16).arg(fh.object).arg(sec_headers.size()));
            }
            image->addRelocation(std::make_unique<core::image::Relocation>(
                    reloc_at,
                    image->symbols()[fh.object - 1], // section alias as base
                    4,                               // 4 byte relocations only
                    dst));                           // offset from section start
        }
    }

    // TODO parseExports();
}

} // namespace le
} // namespace input
} // namespace nc
