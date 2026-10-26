"""Minimal pure-python MaxMind DB reader (enough for GeoLite2-Country lookups)."""
import ipaddress
import struct

MARKER = b"\xab\xcd\xefMaxMind.com"


class Reader:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = f.read()
        idx = self.buf.rfind(MARKER)
        if idx == -1:
            raise ValueError("not an mmdb file")
        meta_start = idx + len(MARKER)
        self.meta, _ = self._decode(meta_start, base=meta_start)
        self.node_count = self.meta["node_count"]
        self.record_size = self.meta["record_size"]
        self.ip_version = self.meta["ip_version"]
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_count * self.node_bytes
        self.data_base = self.tree_size + 16
        self._ipv4_start = None

    # --- data section decoding -------------------------------------------------
    def _decode(self, off, base=None):
        if base is None:
            base = self.data_base
        buf = self.buf
        ctrl = buf[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss = (ctrl >> 3) & 0x3
            vvv = ctrl & 0x7
            if ss == 0:
                ptr = (vvv << 8) | buf[off]
                off += 1
            elif ss == 1:
                ptr = ((vvv << 16) | (buf[off] << 8) | buf[off + 1]) + 2048
                off += 2
            elif ss == 2:
                ptr = ((vvv << 24) | (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]) + 526336
                off += 3
            else:
                ptr = struct.unpack(">I", buf[off:off + 4])[0]
                off += 4
            val, _ = self._decode(base + ptr, base)
            return val, off
        if typ == 0:
            typ = 7 + buf[off]
            off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + buf[off]
            off += 1
        elif size == 30:
            size = 285 + ((buf[off] << 8) | buf[off + 1])
            off += 2
        elif size == 31:
            size = 65821 + ((buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2])
            off += 3
        if typ == 2:
            return buf[off:off + size].decode("utf-8", "replace"), off + size
        if typ == 3:
            return struct.unpack(">d", buf[off:off + 8])[0], off + 8
        if typ == 4:
            return bytes(buf[off:off + size]), off + size
        if typ in (5, 6, 9, 10):
            return int.from_bytes(buf[off:off + size], "big"), off + size
        if typ == 7:
            d = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                d[k] = v
            return d, off
        if typ == 8:
            v = int.from_bytes(buf[off:off + size], "big", signed=False)
            if size == 4 and v >= 2 ** 31:
                v -= 2 ** 32
            return v, off + size
        if typ == 11:
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        if typ == 14:
            return bool(size), off
        if typ == 15:
            return struct.unpack(">f", buf[off:off + 4])[0], off + 4
        return None, off + size

    # --- search tree -------------------------------------------------------------
    def _read_node(self, node, bit):
        off = node * self.node_bytes
        b = self.buf
        rs = self.record_size
        if rs == 24:
            o = off + bit * 3
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if rs == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        if rs == 32:
            o = off + bit * 4
            return struct.unpack(">I", b[o:o + 4])[0]
        raise ValueError("unsupported record size")

    def _ipv4_start_node(self):
        if self._ipv4_start is None:
            node = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._read_node(node, 0)
            self._ipv4_start = node
        return self._ipv4_start

    def get(self, ip_str):
        ip = ipaddress.ip_address(ip_str)
        packed = ip.packed
        if ip.version == 4:
            node = self._ipv4_start_node()
            bits = 32
        else:
            if self.ip_version == 4:
                return None
            node = 0
            bits = 128
        for i in range(bits):
            if node >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node == self.node_count:
            return None
        if node > self.node_count:
            val, _ = self._decode(self.tree_size + (node - self.node_count))
            return val
        return None

    def country(self, ip_str):
        try:
            rec = self.get(ip_str)
        except (ValueError, IndexError):
            return ""
        if not isinstance(rec, dict):
            return ""
        c = rec.get("country") or rec.get("registered_country") or {}
        return c.get("iso_code", "") if isinstance(c, dict) else ""
