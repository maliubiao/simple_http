from cStringIO import StringIO
import socket
from pprint import pprint
import pdb
import sys
import simple_http
import zlib

def _handle_chunked(data, normal_stream):
    prev_chunk = 0
    next_chunk = 0
    this_chunk = 0 
    while True:
        next_chunk = data.find(simple_http.NEWLINE, prev_chunk)
        if next_chunk < 0: return
        try:
            this_chunk = int(data[prev_chunk:next_chunk], 16)
        except: 
            print "prev_chunk", prev_chunk
            print "next_chunk", next_chunk
            pprint(data[prev_chunk-2:].encode("hex"))
            raise socket.error("chunked error")
        next_chunk += 2
        if not this_chunk: return
        normal_stream.write(data[next_chunk: next_chunk+this_chunk])
        prev_chunk = next_chunk + this_chunk + 2


def parse(stream): 
    gzip_maybe = None
    deflate_maybe = None
    chunked_maybe = None
    header_end = stream.find("\r\n\r\n")
    if header_end < 0:
        raise Exception("no header")
    header = simple_http.parse_server_header(stream[:header_end]) 
    if header.get("Content-Encoding") == "gzip":
        gzip_maybe = True
    if header.get("Content-Encoding") == "deflate":
        deflate_maybe = True
    if header.get("Content-Encoding") == "chunked":
        chunked_maybe = True
    stream_buffer = StringIO() 
    content = stream[header_end+4:]
    if chunked_maybe:
        chunked_end = content.rfind("0\r\n\r\n") 
        if chunked_end > -1:
            _handle_chunked(content, stream_buffer)
    else:
        stream_buffer.write(content) 
    final = stream_buffer.getvalue()
    if gzip_maybe:
        final = zlib.decompress(stream_buffer.getvalue(), 16+zlib.MAX_WBITS)
    if deflate_maybe:
        final = zlib.decompress(content_buffer.getvalue(), -zlib.MAX_WBITS)
    stream_buffer.close() 
    return header, final 

if __name__ == "__main__": 
    f = open(sys.argv[1], "r")
    data = f.read()
    f.close()
    print parse(data)
