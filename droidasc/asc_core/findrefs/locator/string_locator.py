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
        # the format does not require the items to be written in string_ids order,
        # so neither the first nor the last entry bounds the region
        offsets = struct.unpack_from(f'<{string_ids_size}I', buf, string_ids_off)
        stridx_map.update(zip(offsets, range(string_ids_size)))
        self.starts = sorted(offsets)
        self.strdata_start = self.starts[0]
        # the item with the largest offset is written last; its terminator closes it
        last = self.starts[-1]
        self.strdata_end = buf.obj.find(
            b'\x00', last + read_uleb128_len(buf, last)
        ) + 1
        self.parsed = True
        self._debug_log("build_map", t_start, len(stridx_map))

    def _match_string_offset(self, string : str):
        buf = self.buf
        # the region below holds MUTF-8, where a code point above the BMP is stored
        # as a surrogate pair (CESU-8) that a UTF-8 pattern can never match. The two
        # encodings agree below the BMP, so only such a pattern pays for the encoder
        # and an ordinary search stays on the plain UTF-8 path.
        pattern_bytes = string.encode('utf-8')
        if any(ord(ch) > 0xFFFF for ch in string):
            from mutf8 import encode_modified_utf8
            pattern_bytes = encode_modified_utf8(string)
        strdata_start = self.strdata_start
        strdata_end = self.strdata_end
        submem = buf[strdata_start: strdata_end]
        pattern = re.compile(pattern_bytes)
        starts = self.starts
        # offsets = []
        for match in pattern.finditer(submem):
            # resolve the item that physically holds the match: its start is the
            # greatest item offset not behind the match, regardless of its index
            pos = bisect_right(starts, strdata_start + match.start()) - 1
            if pos >= 0:
                yield starts[pos]
            # offsets.append(offset + 1) # skip over 00 byte
        # return offsets

    def locate(self, string : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        stridx_map = self.stridx_map
        located_idx = set()
        for offset in self._match_string_offset(string):
            idx = stridx_map.get(offset)
            if idx is not None:
                located_idx.add(idx)
        # return set for O(1) lookup
        self._debug_log("locate", t_start, len(located_idx))
        return located_idx
        
