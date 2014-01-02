from time import time
from struct import pack
from zlib import compressobj
from zlib import crc32
import zlib

compresslevel = 9 
_crc = crc32("") & 0xffffffffL
compresser = compressobj(compresslevel,
        zlib.DEFLATED,
        -zlib.MAX_WBITS,
        zlib.DEF_MEM_LEVEL,
        0) 


def set_compresslevel(compresslevel):
    global compresser, compress
    compresser = compressobj(compresslevel,
            zlib.DEFLATED,
            -zlib.MAX_WBITS,
            zlib.DEF_MEM_LEVEL,
            0) 

def write(src, dst): 
    _compresser = compresser.copy()
    #header
    dst.write("\x1f\x8b\x08\x00") 
    #write time now, 32bit unsigned
    dst.write(pack("<L", long(time()))) 
    dst.write("\x02\xff")
    data = None 
    if isinstance(src, str):
        data = src 
    elif isinstance(src, unicode):
        data = src.encode("utf-8") 
    else:
        data = src.getvalue()
    crc = crc32(data, _crc) & 0xffffffffL 
    dst.write(_compresser.compress(data)) 
    dst.write(_compresser.flush())
    dst.write(pack("<L", crc))
    dst.write(pack("<L", len(data) & 0xffffffffL)) 


