from .base_locator import BaseLocator
from bisect import bisect_right
import struct
from ...utils.leb128 import read_uleb128_len
import re
import time

# Auth: MG1937

# r8 using MUTF8 to handle string payload,
# so 0x00 will be encoded to 0xC0 0x80
class StringLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.stridx_map = {} # {string_data_off : string_idx}
        self.starts = [] # string_data_off of every item, ascending
        self.ordered = False # items written in string_ids order
        self.strdata_start = 0
        self.strdata_end = 0
        self.parsed = False
    
    def _build_map(self):
        if self.parsed:
            return
        t_start = time.perf_counter() if self.debug else None
        string_ids_off, string_ids_size = self.header.strings
        stridx_map = self.stridx_map
        buf = self.buf
        if not string_ids_size:
            self.parsed = True
            self._debug_log("build_map", t_start, 0)
            return
        # string_ids only stores offsets, and the format does not require the items
        # to be written in index order: layout passes such as dexlayout (and the
        # vendor tools that repackage system APKs) permute them. Neither the first
        # nor the last entry bounds the region, so take it from the offsets instead.
        offsets = struct.unpack_from(f'<{string_ids_size}I', buf, string_ids_off)
        stridx_map.update(zip(offsets, range(string_ids_size)))
        starts = sorted(offsets)
        # in index order the item behind a match also carries the next index, so one
        # dict lookup resolves the match. A permuted layout has to search instead,
        # see _locate_by_start, so the layout is recorded once here.
        self.ordered = starts == list(offsets)
        self.starts = starts
        self.strdata_start = starts[0]
        # the item with the largest offset is the one written last; its terminator
        # closes the region
        last = starts[-1]
        self.strdata_end = buf.obj.find(
            b'\x00', last + read_uleb128_len(buf, last)
        ) + 1
        if self.ordered:
            # the final item has no successor, close the lookup with a sentinel that
            # maps to the end of the table
            stridx_map[self.strdata_end] = string_ids_size
        self.parsed = True
        self._debug_log("build_map", t_start, len(stridx_map))

    def _pattern(self, string : str):
        # the region below holds MUTF-8, where a code point above the BMP is stored
        # as a surrogate pair (CESU-8) that a UTF-8 pattern can never match. The two
        # encodings agree below the BMP, so only such a pattern pays for the encoder
        # and an ordinary search stays on the plain UTF-8 path.
        pattern_bytes = string.encode('utf-8')
        if any(ord(ch) > 0xFFFF for ch in string):
            from mutf8 import encode_modified_utf8
            pattern_bytes = encode_modified_utf8(string)
        return re.compile(pattern_bytes)

    def _locate_by_start(self, match_start, match_end):
        """Resolve a match to the item that holds it when the layout is permuted."""
        starts = self.starts
        pos = bisect_right(starts, match_start) - 1
        if pos < 0:
            return None
        # the item ends where the next one starts, so the match may not reach it
        boundary = starts[pos + 1] if pos < len(starts) - 1 else self.strdata_end
        if match_end >= boundary:
            return None
        return self.stridx_map[starts[pos]]

    def locate(self, string : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        stridx_map = self.stridx_map
        ordered = self.ordered
        buf = self.buf
        mm = buf.obj
        strdata_start = self.strdata_start
        strdata_end = self.strdata_end
        located_idx = set()
        for match in self._pattern(string).finditer(buf[strdata_start:strdata_end]):
            match_start = strdata_start + match.start()
            match_end = strdata_start + match.end()
            # the payload ends at the first terminator behind the match start, since
            # a MUTF-8 payload never holds 0x00 on its own. A match that reaches past
            # it runs through the terminator into the following item.
            terminator = mm.find(b'\x00', match_start, strdata_end)
            if terminator < match_end:
                continue
            if ordered:
                # the item written behind this one carries the next index, so its
                # index minus one is the item that ends at this terminator
                idx = stridx_map.get(terminator + 1)
                if idx is not None:
                    located_idx.add(idx - 1)
                    continue
            idx = self._locate_by_start(match_start, match_end)
            if idx is not None:
                located_idx.add(idx)
        # return set for O(1) lookup
        self._debug_log("locate", t_start, len(located_idx))
        return located_idx
        
