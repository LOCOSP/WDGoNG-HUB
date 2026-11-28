"""Tiny PNG decoder for EXTRAS images. Pure stdlib (struct + zlib), no raylib.

Extras may ship a few SMALL images (an icon, a logo). They are decoded here -
inside the sandbox for third-party extras - into raw RGBA, and only those raw
pixels, with their size re-checked, ever reach the game's renderer. The game
process never hands a third-party file to a native image library. The single
image the game decodes itself is a hub extra's tiny icon.png, with this module,
and only from content that matches the signed catalogue (see HubScreen._icon).

Deliberately narrow: 8-bit greyscale / RGB / grey+alpha / RGBA, and greyscale or
palette at 1, 2 or 4 bits (what image tools write for small palettes); non-interlaced, at most IMG_MAX_PX on a side. Anything else is refused with a
ValueError that says why, so an author sees the reason in the simulator.
"""
import struct
import zlib

IMG_MAX_PX = 512                # width and height limit, pixels
IMG_MAX_BYTES = 256 * 1024      # one .png file
IMG_MAX_COUNT = 8               # .png files per extra
IMG_MAX_TOTAL = 512 * 1024      # all .png files of one extra together
ICON_NAME = "icon.png"          # optional listing icon, with tighter limits:
ICON_MAX_PX = 64
ICON_MAX_BYTES = 16 * 1024

_SIG = b"\x89PNG\r\n\x1a\n"
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def header(data: bytes):
    """(width, height) from the IHDR chunk alone - no inflation, no pixel work.
    Raises ValueError when the file does not start like a PNG."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 33 or data[:8] != _SIG:
        raise ValueError("not a PNG file")
    (n,) = struct.unpack(">I", data[8:12])
    if n != 13 or data[12:16] != b"IHDR":
        raise ValueError("bad PNG (no header first)")
    if zlib.crc32(data[12:29]) & 0xFFFFFFFF != struct.unpack(">I", data[29:33])[0]:
        raise ValueError("corrupt PNG (checksum)")
    w, h = struct.unpack(">II", data[16:24])
    return w, h


def decode_icon(data: bytes):
    """The listing icon: (w, h, rgba), decoded ONCE. Byte and pixel limits are
    enforced before anything is inflated. Raises ValueError."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > ICON_MAX_BYTES:
        raise ValueError("icon.png is %d bytes - the limit is %d"
                         % (len(data) if isinstance(data, (bytes, bytearray)) else -1, ICON_MAX_BYTES))
    w, h = header(data)
    if not (1 <= w <= ICON_MAX_PX and 1 <= h <= ICON_MAX_PX):
        raise ValueError("icon.png is %dx%d - the limit is %dx%d" % (w, h, ICON_MAX_PX, ICON_MAX_PX))
    return decode(data, max_px=ICON_MAX_PX)


def check_icon(data: bytes):
    """The listing icon must be tiny. Returns (w, h); raises ValueError."""
    w, h, _ = decode_icon(data)
    return w, h


def decode(data: bytes, max_px: int = IMG_MAX_PX):
    """PNG bytes -> (width, height, rgba_bytes). Raises ValueError. `max_px` (at most
    IMG_MAX_PX) is checked at the header, before any pixel data is inflated."""
    max_px = max(1, min(IMG_MAX_PX, int(max_px)))
    if not isinstance(data, (bytes, bytearray)) or len(data) > IMG_MAX_BYTES:
        raise ValueError("image larger than %d bytes" % IMG_MAX_BYTES)
    if data[:8] != _SIG:
        raise ValueError("not a PNG file")
    pos, w = 8, 0
    h = ctype = 0
    plte = trns = None
    idat = []
    seen_end = False
    while pos + 12 <= len(data):
        (n,) = struct.unpack(">I", data[pos:pos + 4])
        kind = data[pos + 4:pos + 8]
        if n > len(data) - pos - 12:
            raise ValueError("truncated PNG")
        body = data[pos + 8:pos + 8 + n]
        if zlib.crc32(kind + body) & 0xFFFFFFFF != struct.unpack(">I", data[pos + 8 + n:pos + 12 + n])[0]:
            raise ValueError("corrupt PNG (checksum)")
        pos += 12 + n
        if kind == b"IHDR":
            if n != 13 or w:
                raise ValueError("bad PNG header")
            w, h, depth, ctype, comp, flt, lace = struct.unpack(">IIBBBBB", body)
            if not (1 <= w <= max_px and 1 <= h <= max_px):
                raise ValueError("image is %dx%d - the limit is %dx%d" % (w, h, max_px, max_px))
            if ctype not in _CHANNELS or comp or flt or not (
                    depth == 8 or (depth in (1, 2, 4) and ctype in (0, 3))):
                raise ValueError("unsupported PNG format (need 8-bit grey/RGB/RGBA, "
                                 "or a 1/2/4/8-bit palette or greyscale)")
            if lace:
                raise ValueError("interlaced PNG is not supported")
        elif not w:
            raise ValueError("bad PNG (no header first)")
        elif kind == b"PLTE":
            plte = body
        elif kind == b"tRNS":
            trns = body
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            seen_end = True
            break
    if not w or not idat or not seen_end:
        raise ValueError("incomplete PNG")
    ch = _CHANNELS[ctype]
    stride = (w * ch * depth + 7) // 8                  # bytes per row
    need = (stride + 1) * h
    z = zlib.decompressobj()
    raw = z.decompress(b"".join(idat), need + 1)       # never inflate more than one image's worth
    if len(raw) != need or z.unconsumed_tail:
        raise ValueError("corrupt PNG (pixel data size)")
    # undo the per-row filters
    px = bytearray(stride * h)
    prev = bytes(stride)
    ch = max(1, ch * depth // 8)                        # filter distance in bytes
    for y in range(h):
        f = raw[y * (stride + 1)]
        row = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        if f == 1:
            for i in range(ch, stride):
                row[i] = (row[i] + row[i - ch]) & 255
        elif f == 2:
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 255
        elif f == 3:
            for i in range(stride):
                left = row[i - ch] if i >= ch else 0
                row[i] = (row[i] + ((left + prev[i]) >> 1)) & 255
        elif f == 4:
            for i in range(stride):
                a = row[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                row[i] = (row[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        elif f != 0:
            raise ValueError("corrupt PNG (row filter)")
        px[y * stride:(y + 1) * stride] = row
        prev = bytes(row)
    if depth < 8:                                       # unpack to one byte per sample
        mask, per = (1 << depth) - 1, 8 // depth
        up = bytearray(w * h)
        for y in range(h):
            row = px[y * stride:(y + 1) * stride]
            for x in range(w):
                up[y * w + x] = (row[x // per] >> (8 - depth * (x % per + 1))) & mask
        if ctype == 0:                                  # greyscale: stretch to 0..255
            for i in range(w * h):
                up[i] = up[i] * 255 // mask
            if trns and len(trns) >= 2:
                trns = bytes((0, trns[1] * 255 // mask))
        px = up
    # expand to RGBA
    out = bytearray(w * h * 4)
    n = w * h
    if ctype == 6:
        out[:] = px
    elif ctype == 2:
        tr = tuple(trns[1::2][:3]) if trns and len(trns) >= 6 else None
        for i in range(n):
            r, g, b = px[3 * i], px[3 * i + 1], px[3 * i + 2]
            out[4 * i:4 * i + 4] = bytes((r, g, b, 0 if tr == (r, g, b) else 255))
    elif ctype == 0:
        tr = trns[1] if trns and len(trns) >= 2 else None
        for i in range(n):
            v = px[i]
            out[4 * i:4 * i + 4] = bytes((v, v, v, 0 if tr == v else 255))
    elif ctype == 4:
        for i in range(n):
            v = px[2 * i]
            out[4 * i:4 * i + 4] = bytes((v, v, v, px[2 * i + 1]))
    else:                                               # palette
        if not plte or len(plte) % 3:
            raise ValueError("corrupt PNG (palette)")
        ncol = len(plte) // 3
        for i in range(n):
            v = px[i]
            if v >= ncol:
                raise ValueError("corrupt PNG (palette index)")
            a = trns[v] if trns and v < len(trns) else 255
            out[4 * i:4 * i + 4] = bytes((plte[3 * v], plte[3 * v + 1], plte[3 * v + 2], a))
    return w, h, bytes(out)
