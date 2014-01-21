"""
document 
server_cookie_decode(server_cookie_string) 
server_cookie =[
            {"cookie": "k=v", "path": "/", "expires": "..."},
            {"cookie": "n=v", "path": "/", "expires": "..."},
            {...}
        ]
server_cookie_encode(server_cookie)
->"k=v; path=/; expires=someday\r\nn=v......" 

server_cookie_get(server_cookie)
client_cookie_encode(client_cookie)
->"k=v; n=v"
client_cookie = client_cookie_decode(cookie)
->{"k": "v"; "n": "v"}
s.get(url, cookie=client_cookie)

"""

import os.path 
import socket
import io 
import zlib
import pdb 
import signal
import base64
import json

from uuid import uuid4
from struct import pack, unpack
from cStringIO import StringIO 
from collections import OrderedDict


try:
    import ssl
    ssl_maybe = True
except:
    ssl_maybe = False

if os.path.exists("bug.log"):
    bug_logger = open("bug.log", "r+")
    bug_logger_fd = os.dup(bug_logger.fileno())
    bug_logger.close()
else:
    bug_logger = open("bug.log", "w")
    bug_logger_fd = os.dup(bug_logger.fileno())
    bug_logger.close()

default_header = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3", 
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/25.0"
        } 

common_mimetypes = {
        "pdf": "application/pdf",
        "zip": "application/zip",
        "gz": "application/x-gzip",
        "doc": "application/msword",
        "ogg": "application/ogg",
        "default": "application/octet-stream",
        "json": "application/json",
        "xml": "application/xml",
        "js": "application/x-javascript", 
        "7z": "application/x-7z-compressed",
        "deb": "application/x-deb",
        "tar": "application/x-tar",
        "swf": "application/x-shockwave-flash",
        "torrent": "application/x-bittorrent",
        "bmp": "image/bmp",
        "gif": "image/gif",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "svg": "image/svg+xml",
        "tiff": "image/tiff",
        "mp3": "audio/mpeg",
        "wav": "audio/x-wav", 
        "css": "text/css",
        "text": "text/plain",
        "html": "text/html",
        "vcard": "text/vcard",
        "md": "text/x-markdown",
        "mov": "video/quicktime",
        "mp4": "video/mp4",
        "mkv": "video/x-matroska",
        "wmv": "video/x-ms-wmv",
        "flv": "video/x-flv",
        "mpg": "video/mpeg",
        "mpeg": "video/mpeg"
        }


#http consts
http_message = {
        100: "100 Continue",
        101: "101 Switching Protocols",
        102: "102 Processing",
        200: "200 OK",
        201: "201 Created",
        202: "202 Accepted",
        203: "203 Non-Authoritative Information",
        204: "204 No Content",
        205: "205 Reset Content",
        206: "206 Partial Content",
        300: "300 Multiple Choices",
        301: "301 Moved Permanently",
        302: "302 Found",
        303: "303 See Other",
        304: "304 Not Modified",
        305: "305 Use Proxy",
        306: "306 Switch Proxy",
        307: "307 Temporary Redirect", 
        400: "400 Bad Request",
        401: "401 Unauthorized",
        402: "402 Payment Required",
        403: "403 Forbidden", 
        404: "404 Not Found",
        405: "405 Method Not Allowed",
        406: "406 Not Acceptable", 
        407: "407 Proxy Authentication Required",
        408: "408 Request Timeout",
        409: "409 Conflict",
        410: "410 Gone",
        411: "411 Length Required",
        412: "412 Precondition Failed",
        413: "413 Request Entity Too Large",
        414: "414 Request-URI Too Long",
        415: "415 Unsupportd Media Type",
        416: "416 Requested Range Not Satisfiable",
        417: "417 Expectation Failed",
        418: "418 I'm a teapot",
        421: "421 There are too many connections from your Internet Address",
        422: "422 Unprocessable Entity",
        423: "423 Locked",
        424: "424 Failed Dependency",
        425: "425 Unordered Collection",
        426: "426 Upgrade Required",
        449: "449 Retry With",
        500: "500 Internal Server Error",
        501: "501 Not implemented",
        502: "502 Bad Gateway",
        503: "503 Service Unavailable",
        504: "504 Gateway Timeout",
        505: "505 HTTP Version Not Supported",
        506: "506 Variant Also Negotiates",
        507: "507 Insufficient Storage",
        509: "509 Bandwidth Limit Exceeded",
        510: "Not Extended"
        }


default_timeout = 20 

HTTP_VERSION = "HTTP/1.1"
HEADER_END = "\x0d\x0a\x0d\x0a"
NEWLINE = "\x0d\x0a"
METHOD_GET = "GET "
METHOD_POST = "POST "
METHOD_DELETE = "DELETE "
"""
COOKIE = "cookie"
COOKIE_VERSION = "Version"
COOKIE_COMMENT = "Comment"
COOKIE_COMMENTURL = "CommentUrl"
COOKIE_DISCARD = "Discard"
COOKIE_DOMAIN = "Domain"
COOKIE_MAXAGE = "Maxage"
COOKIE_PATH = "Path"
COOKIE_PORT = "Port"
COOKIE_SECURE = "Secure"
COOKIE_FORMAT = ';%s=%s'
""" 

COOKIE = "Cookie"
SET_COOKIE = "Set-Cookie"

CONTENT_ENCODING = "Content-Encoding"
CONTENT_TYPE = "Content-Type"
TRANSFER_ENCODING = "Transfer-Encoding"
CONTENT_LENGTH = "Content-Length"

BOUNDARY = uuid4().hex
BOUNDARY_STRING = "--%s\r\n" % BOUNDARY
BOUNDARY_END = "--%s--" % BOUNDARY
FORM_FILE = 'Content-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n' 
FORM_STRING = 'Content-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' 

FORM_SIMPLE_TYPE = "application/x-www-form-urlencoded"
FORM_COMPLEX_TYPE = "multipart/form-data; boundary=%s" % BOUNDARY


#ascii -> %hex
hex_string_table = {} 
#%hex -> ascii
string_hex_table = {}        
#url reversed characters 
urhs_table = { 
        0x21: "%21", #!
        0x23: "%23", ##
        0x24: "%24", #$
        0x26: "%26", #&
        0x27: "%27", #'
        0x28: "%28", #(
        0x29: "%29", #)
        0x2A: "%2A", #*
        0x2B: "%2B", #+
        0x2C: "%2C", #,
        0x2F: "%2F", #/
        0x3A: "%3A", #:
        0x3B: "%3B", #;
        0x3D: "%3D", #=
        0x3F: "%3F", #?
        0x40: "%40", #@
        0x5B: "%5B", #[
        0x5D: "%5D" #]
        }
#url common characters
uchs_table = {
        0x20: "%20", #space
        0x22: "%22", #"
        0x25: "%25", #%
        0x2D: "%2D", #-
        #0x2E: "%2E", #.
        0x3C: "%3C", #<
        0x3E: "%3E", #>
        0x5C: "%5C", #\
        0x5E: "%5E", #^
        #0x5F: "%5F", #_                
        0x60: "%60", #`
        0x7B: "%7B", #{
        0x7C: "%7C", #|
        0x7D: "%7D", #}
        0x7E: "%7E" #~
        }

def init_string_hex_table():
    for char in range(0x00, 0xff+1):
        string_hex_table[char] = "%" + chr(char).encode("hex").upper()
def init_hex_string_table():
    for char in range(0x00, 0xff+1):
        hex_string_table["%" + chr(char).encode("hex").upper()] = char

init_hex_string_table()
init_string_hex_table() 


def get(url, query=None, header=None, cookie = None, proxy = None, timeout=0, callback = None):
    return general_get(url, query, header, cookie, proxy, timeout, callback, httpmethod="GET ")

def general_get(url, query=None, header=None, cookie=None, proxy = None, timeout = 0, callback=None, httpmethod="GET "): 
    request_buffer = StringIO() 
    url_dict = url_decode(url) 
    #http basic authorization 
    basicauth = None
    if url_dict.get("user"):
        if url_dict.get("password"):
            basicauth = "Basic %s" % base64.b64encode(
                        "%s:%s" % (url_dict["user"], url_dict["password"]))
            del url_dict["user"]
            del url_dict["password"]
        else:
            raise Exception("Basic Authentication need your password") 
    #http proxy, mangle header
    http_proxy = None
    if proxy:
        proxy_dict = url_decode(proxy) 
        if proxy_dict["scheme"] == "http":
            if proxy_dict.get("user"):
                http_proxy = "Basic %s" % base64.b64encode(
                            "%s:%s" % (proxy_dict["user"], proxy_dict["password"])) 
            else:
                http_proxy = " "
    #maybe ssl connection
    use_ssl = False 
    if url_dict.get("scheme"):
        if url_dict.get("scheme") == "https":
            use_ssl = True
        if not http_proxy:
            del url_dict["scheme"] 
    if use_ssl:
        if not ssl_maybe:
            request_buffer.close()
            raise Exception("Unsupported scheme")
        port = 443 
    else:
        port = 80 
    if url_dict.get("port"):
        port = url_dict["port"]
        if not http_proxy:
            del url_dict["port"] 
    #handle query string
    if query:
        url_dict["query"] = "?%s" % ("&".join(["=".join((url_escape(k),
                                url_escape(v))) for k,v in query.items()]))
    host = url_dict["host"] 
    if not http_proxy:
        del url_dict["host"] 
    path = url_encode(url_dict) 
    if not header: header = default_header.copy() 
    if httpmethod:
        header["METHOD"] = httpmethod
    header["PATH"] = path 
    header["Host"] = "%s:%d" % (host, port) 
    #mangle header for basic authorization
    if basicauth: header["Authorization"] = basicauth 
    #mangle header for basic proxy authorization
    if http_proxy: header["Proxy-Authorization"] = http_proxy 
    request_buffer.write(header_encode(header)) 
    #generate cookie and HEADER_END
    if cookie:
        request_buffer.write("Cookie: ")    
        request_buffer.write(client_cookie_encode(cookie)) 
        request_buffer.write(HEADER_END) 
    else:
        request_buffer.write(NEWLINE)
    final = request_buffer.getvalue()    
    request_buffer.close() 
    connection = (host, port) 
    if not callback:
        return sync_get(connection, use_ssl, final, proxy = proxy, timeout=timeout)
    else:
        return async_get(connection, use_ssl, final, callback=callback, timeout=timeout) 
        
def handle_chunked(data, normal_stream):
    prev_chunk = 0
    next_chunk = 0
    this_chunk = 0 
    while True:
        next_chunk = data.find(NEWLINE, prev_chunk)
        if next_chunk < 0: return
        try:
            this_chunk = int(data[prev_chunk:next_chunk], 16)
        except: 
            raise socket.error("chunked error")
        next_chunk += 2
        if not this_chunk: return
        normal_stream.write(data[next_chunk: next_chunk+this_chunk])
        prev_chunk = next_chunk + this_chunk + 2

f = open("test", "w")
def wait_response(connection, normal_stream, timeout=0):
    total_length = 0xffffffff 
    chunked_maybe = False 
    length_unkown = False
    gzip_maybe = False
    deflate_maybe = False
    header = None 
    cookie = None
    header_maybe = False 
    header_buffer = StringIO()
    content_buffer = StringIO()
    ranges_maybe = False
    average = 0 
    average_count = 0
    read_count = 4096 
    noheader = 0 
    #if recv blocks, interrupt syscall after timeout
    if timeout:
        signal.alarm(timeout) 
        def wait_timeout(signum, frame):
            return
        signal.signal(signal.SIGALRM, wait_timeout)
    while True: 
        try:
            data = connection.recv(int(read_count)) 
            f.write(data)
            f.flush() 
        #interrupted syscall
        except socket.error, err:
            data = content_buffer.getvalue()
            normal_stream.write(data)
            content_buffer.close() 
            os.write(bug_logger_fd, json.dumps({
                "err": str(err),
                "data": data,
                "header": header
                })+"\n") 
            return gzip_maybe, deflate_maybe, cookie, header 
        #dynamic read_count control
        average_count += 1 
        average += len(data) 
        if average_count == 2: 
            if average / average_count > (0.8*read_count):
                read_count = 1.25*read_count
            else:
                read_count = 0.8*read_count
            average = 0
            average_count = 0 
        #read header 
        if not header_maybe: 
            if header_buffer:
                header_buffer.write(data) 
                data = header_buffer.getvalue()                
            header_end = data.find(HEADER_END) 
            if header_end < 0: 
                noheader += 1 
                if noheader > 2:
                    content_buffer.close()
                    raise socket.error("header too large or not a header")
                else:
                    header_buffer.write(data)
                    continue
            else:
                header_buffer.close()
            header, cookie = header_decode(data[:header_end]) 
            if CONTENT_LENGTH in header:
                total_length = int(header[CONTENT_LENGTH])
            else:
                length_unkown = True 
            #maybe chunked stream
            if header.get(TRANSFER_ENCODING) == "chunked": 
                chunked_maybe = True
            #maybe gzip stream
            if header.get(CONTENT_ENCODING) == "gzip": 
                gzip_maybe = True 
            if header.get(CONTENT_ENCODING) == "deflate":
                deflate_maybe = True
            if header.get("Accept-Ranges") == "bytes":
                ranges_maybe = True
                length_unkown = True
            if header.get("Content-Range"):
                length_unkown = False 
            data = data[header_end+4:] 
            if not gzip_maybe and not chunked_maybe and not ranges_maybe and length_unkown and not deflate_maybe and not data:
                break
            header_maybe = True 
        content_buffer.write(data) 
        #handle chunked data
        if chunked_maybe:
            chunked_end = data.rfind("0\r\n\r\n")
            if chunked_end > -1: 
                handle_chunked(content_buffer.getvalue(), normal_stream)
                content_buffer.close()
                return gzip_maybe, deflate_maybe, cookie, header 
        #if we don't know the end, assume HEADER_END
        if length_unkown and not chunked_maybe:
            entity_end = data.rfind(HEADER_END)
            if entity_end == (len(data) -4): 
                break 
        #Content-Length
        if content_buffer.tell() >= total_length:
            break; 
        #no more data
        if header.get("Connection") == "close" and length_unkown and not chunked_maybe:
            break
    normal_stream.write(content_buffer.getvalue())
    content_buffer.close()
    return gzip_maybe, deflate_maybe, cookie, header

def send_http(connection, use_ssl, message, proxy=None, timeout=0): 
    try: 
        content_buffer = StringIO() 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        #if there is a proxy , connect proxy server instead
        proxy_type = None 
        if proxy:
            proxy_dict = url_decode(proxy)
            if proxy_dict["scheme"] == "socks5":
                proxy_type = "socks5"
                proxy_server = (proxy_dict["host"], proxy_dict["port"]) 
                sock.connect(proxy_server) 
                #socks5 handshake
                sock.send("\x05\x01\x00") 
                if not sock.recv(4).startswith("\x05\x00"): 
                    sock.close()
                    raise Exception("connect proxy failed") 
                #use remote dns by default
                sock.send("\x05\x01\x00\x03%s%s%s" % (pack("B",
                    len(connection[0])),
                    connection[0],
                    pack(">H", connection[1])))
                #if request failed
                if not sock.recv(12).startswith("\x05\x00"): 
                    sock.close()
                    raise Exception("proxy network error")
            elif proxy_dict["scheme"] in "https": 
                proxy_type = "http"
                proxy_server = (proxy_dict["host"], proxy_dict["port"]) 
                sock.connect(proxy_server) 
            else:
                raise Exception("unknown proxy type")
        else:
            sock.connect(connection)
        #if scheme == "https"
        if use_ssl and proxy_type != "http":
            sock = ssl.wrap_socket(sock) 
        sock.send(message) 
        gzip_maybe, deflate_maybe, cookie, header = wait_response(sock, content_buffer, timeout=timeout)
    except socket.error, err: 
        content_buffer.close()
        sock.close()
        raise err 
    sock.close()

    #handle compressed stream: gzip, deflate 
    try:
        if gzip_maybe:
            final = zlib.decompress(content_buffer.getvalue(), 16+zlib.MAX_WBITS) 
        if deflate_maybe:
            final = zlib.decompress(content_buffer.getvalue(), -zlib.MAX_WBITS) 
        if not gzip_maybe and not deflate_maybe:
            final = content_buffer.getvalue() 
    except: 
        pdb.set_trace()
    content_buffer.close() 
    return header, cookie, final

def sync_get(connection, use_ssl, message, proxy=None, timeout=0): 
    return send_http(connection, use_ssl, message, proxy=proxy, timeout=timeout) 

def sync_post(connection, use_ssl, message, proxy=None, timeout=0):
    return send_http(connection, use_ssl, message, proxy=proxy, timeout=timeout)

def post(url, payload, header=None, cookie=None, proxy=None, callback=None, timeout=0): 
    content_buffer = StringIO()
    request_buffer = StringIO() 
    use_ssl = False 
    url_dict = url_decode(url) 
    #http basic authorization
    basicauth = None
    if url_dict.get("user"):
        if url_dict.get("password"):
            basicauth = "Basic %s" % base64.b64encode("%s:%s" % (url_dict["user"],
                            url_dict["password"]))
            del url_dict["user"]
            del url_dict["password"]
        else:
            raise Exception("Basic Authentication need your password") 
    #http proxy, mangle header
    http_proxy = None
    if proxy:
        proxy_dict = url_decode(proxy) 
        if proxy_dict["scheme"] == "http":
            if proxy_dict.get("user"):
                http_proxy = "Basic %s" % base64.b64encode("%s:%s" % (proxy_dict["user"],
                            proxy_dict["password"])) 
    #generate PATH 
    if "scheme" in url_dict:
        if url_dict["scheme"] == "https":
            use_ssl = True
        if not http_proxy:
            del url_dict["scheme"] 
    host = url_dict["host"] 
    del url_dict["host"] 
    #maybe ssl connection
    if use_ssl:
        if not ssl_maybe:
            content_buffer.close()
            request_buffer.close()
            raise Exception("Unsupported scheme")
        port = 443 
    else:
        port = 80 
    if "port" in url_dict:
        port = url_dict["port"]
        if not http_proxy:
            del url_dict["port"] 
    path = url_encode(url_dict) 
    #use multipart/form-data or not
    file_maybe = False 
    for k,v in payload.items(): 
        if not (isinstance(v, str) or
                isinstance(v, unicode) or
                isinstance(v, file)): 
            content_buffer.close()
            request_buffer.close()
            raise Exception("payload value: str or unicode or fileobject")
        if isinstance(v, file):
            file_maybe = True 

    if not header: header = default_header.copy() 
    header["Host"] = "%s:%d" % (host, port) 
    if not file_maybe:
        header[CONTENT_TYPE] = FORM_SIMPLE_TYPE
    else:
        header[CONTENT_TYPE] = FORM_COMPLEX_TYPE 
    #generate multipart stream
    if file_maybe: 
        for k, v in payload.items():
            if isinstance(v, str) or isinstance(v, unicode):
                content_buffer.write(BOUNDARY_STRING)
                content_buffer.write(FORM_STRING % (k, v)) 
            if isinstance(v, file):
                filename = os.path.basename(v.name)
                if not filename:
                    filename = "unknown" 
                content_buffer.write(BOUNDARY_STRING)
                content_buffer.write(FORM_FILE % (k, filename,
                                    auto_content_type(filename))) 
                content_buffer.write(v.read())
                content_buffer.write(NEWLINE) 
        content_buffer.write(BOUNDARY_END)
    else:
        content_buffer.write("&".join(["=".join((url_escape(k),
                            url_escape(v))) for k, v in payload.items()])) 
    header[CONTENT_LENGTH] = str(content_buffer.tell())
    header["PATH"]  = path
    header["METHOD"] = METHOD_POST
    #mangle header for basic authorization
    if basicauth: header["Authorization"] = basicauth 
    #mangle header for basic proxy authorization
    if http_proxy: header["Proxy-Authorization"] = http_proxy
    request_buffer.write(header_encode(header)) 
    #generate cookie and HEADER_END
    if cookie:
        request_buffer.write("Cookie: ")    
        request_buffer.write(client_cookie_encode(cookie)) 
        request_buffer.write(HEADER_END)
    else:
        request_buffer.write(NEWLINE)
    request_buffer.write(content_buffer.getvalue()) 
    content_buffer.close() 
    message = request_buffer.getvalue() 
    request_buffer.close() 
    return sync_post((host, port), use_ssl, message, proxy=proxy, timeout=timeout) 

def url_escape(url):
    buf = StringIO()
    if isinstance(url, unicode):
        url = bytearray(url, "utf-8")
    else:
        url = bytearray(url)
    for char in url: 
        if char in urhs_table:
            buf.write(urhs_table[char])
        elif char in uchs_table:
            buf.write(uchs_table[char])
        else: 
            buf.write(chr(char))
    final = buf.getvalue()
    buf.close()
    return final

def url_unescape(url):
    buf = StringIO()
    i = 0
    ulen = len(url)
    while i < ulen:
        char = url[i]
        if char == "%":
            buf.write(chr(hex_string_table[url[i:i+3]]))
            i = i+ 3
        else:
            buf.write(char)
            i += 1
    final = buf.getvalue()
    buf.close()
    return final

def auto_content_type(name):
    dot_offset = name.find(".") 
    if dot_offset < 0:
        return common_mimetypes["default"] 
    else:
        return common_mimetypes.get(name[dot_offset+1:], common_mimetypes["default"]) 

def url_encode(url_dict):
    url_buffer = StringIO()
    if "scheme" in url_dict:
        url_buffer.write(url_dict["scheme"])
        url_buffer.write('://') 
    if "user" in url_dict:
        url_buffer.write(url_dict["user"])
        if "password" in url_dict: 
            url_buffer.write(":")
            url_buffer.write(url_dict["password"])
        url_buffer.write("@")
    if "host" in url_dict: 
        url_buffer.write(url_dict["host"]) 
    if "port" in url_dict:
        url_buffer.write(":")
        url_buffer.write(str(port))
    if "PATH" in url_dict: 
        if not url_dict["PATH"].startswith("/"):
            url_buffer.write("/")
        if not url_dict["PATH"].endswith("/"): 
            url_buffer.write(url_dict["PATH"])
        else: 
            url_buffer.write(url_dict["PATH"]) 
    if "query" in url_dict: 
        url_buffer.write(url_dict["query"])
    if "params" in url_dict: 
        url_buffer.write(";")
        url_buffer.write(";".join(url_dict["params"])) 
    if "frag" in url_dict:  
        url_buffer.write(url_dict["frag"])
    final = url_buffer.getvalue()
    url_buffer.close()
    return final

def url_decode(url):
    url_dict = {} 
    url_find = url.find 
    protocol_maybe = url_find("://") 
    account_maybe = url_find("@") 
    last = 0
    if protocol_maybe > -1:
        current_part = protocol_maybe
        url_dict["scheme"] = url[:protocol_maybe] 
        last = protocol_maybe + 3  
    else:
        url_dict["scheme"] = "http"
    if account_maybe > -1:
        semi_maybe = url_find(":", last, account_maybe)
        if semi_maybe > -1:
            url_dict["user"] = url[last:semi_maybe]
            url_dict["password"] = url[semi_maybe:account_maybe]
        else:
            url_dict["user"] = url[last:account_maybe]
        last = account_maybe
    path_maybe = url_find("/", last)        
    if path_maybe > -1:
        port_maybe = url_find(":", last, path_maybe)
        if port_maybe > -1: 
            url_dict["host"] = url[last:port_maybe]
            url_dict["port"] = int(url[port_maybe+1:path_maybe])
        else:
            url_dict["host"] = url[last:path_maybe]
        last = path_maybe
    else:        
        port_maybe = url_find(":", last)
        if port_maybe > -1:
            url_dict["host"] = url[last:port_maybe]
            url_dict["port"] = int(url[port_maybe+1:])
        else:
            url_dict["host"] = url[last:]
        url_dict["PATH"] = "/"
        return url_dict 
    ulen = len(url)
    i = last
    path_found = 0
    query_found = 0
    params_found = 0
    frag_found = 0 
    next_path_maybe = path_maybe + 1
    while i < ulen:
        char = url[i]
        if char == "?":
            if i == next_path_maybe:
                url_dict["PATH"] = "/"
                continue
            if not path_found:
                url_dict["PATH"] = url[last:i]
                path_found = 1
            frag_maybe = url_find("#", i)
            params_maybe= url_find(";", i)
            x = min(frag_maybe, params_maybe)
            y = max(frag_maybe, params_maybe) 
            if x > -1:
                url_dict["query"] = url[i:x]
                query_found = 1
            else:
                if y > -1:
                    url_dict["query"] = url[i:y] 
                    query_found = 1
                else:
                    url_dict["query"] = url[i:]
                    query_found = 1
                    break
        elif char == "#":             
            if i == next_path_maybe:
                url_dict["PATH"] = "/"
                continue
            if not path_found:
                url_dict["PATH"] = url[last:i]
                path_found = 1
            query_maybe = url_find("?", i)
            params_maybe = url_find(";", i)
            x = min(query_maybe, params_maybe)
            y = max(query_maybe, params_maybe)
            if x > -1:
                url_dict["frag"] = url[i:x]
                frag_found = 1
            else:
                if y > -1:
                    url_dict["frag"] = url[i:y]
                    frag_found = 1
                else:
                    url_dict["frag"] = url[i:]
                    frag_found = 1
                    break
        elif char == ";":
            if i == next_path_maybe:
                url_dict["PATH"] = "/"
                continue
            if not path_found:
                url_dict["PATH"] = url[lat:i]
                path_found = 1
            query_maybe = url_find("?", i)
            frag_maybe = url_find("#", i)
            x = min(query_maybe, frag_maybe)
            y = max(query_maybe, frag_maybe)
            if x > -1:
                url_dict["params"] = url[i:x]
                params_found = 1
            else:
                if y > -1:
                    url_dict["params"] = url[i:y]
                    params_found = 1
                else:
                    url_dict["params"] =  url[i:]
                    params_found = 1
                    break
        i += 1 
    if not any((params_found, query_found, frag_found)):
        url_dict["PATH"] = url[last:]
    return url_dict
    
def server_cookie_get(server_cookie):
    buf = StringIO()
    for cookie in server_cookie:
        buf.write("%s; " % cookie["cookie"])
    buf.truncate(buf.tell() - 2) 
    final = buf.getvalue() 
    buf.close()
    return final

def client_cookie_encode(client_dict):
    buf = StringIO()
    for k,v in client_dict.items():
        buf.write("%s=%s; " % (k,v))
    buf.truncate(buf.tell() - 2)
    final = buf.getvalue()
    buf.close()
    return final

def client_cookie_decode(client_cookie):
    cookie_dict = {}
    for cookie in client_cookie.split(";"):
        kv = cookie.split("=")
        cookie_dict[kv[0].strip()] = kv[1].strip()
    return cookie_dict

def server_cookie_encode(cookie_list):
    buf = StringIO()
    for cookie_dict in cookie_list:
        for k,v in cookie_dict.items():
            if k == "cookie":
                buf.write('%s; ' % v)
                continue
            buf.write('%s=%s; ' % (k, v))
        buf.truncate(buf.tell() - 2)
        buf.write(NEWLINE)
    buf.truncate(buf.tell() - 2)
    final = buf.getvalue() 
    buf.close()
    return final

def server_cookie_decode(cookie):
    cookie_list = [] 
    for line in cookie.split(NEWLINE):
        cookie_dict = OrderedDict()
        for index, part in enumerate(line.split(";")):
            #cookie, kv
            if not index:
                cookie_dict["cookie"] = part
                continue
            #options
            equal_mark = part.find("=")
            #maybe k=v; httponly
            if equal_mark > -1:
                cookie_dict[part[:equal_mark].strip().lower()] = part[equal_mark+1:]
            else:
                cookie_dict[part] = ""
        cookie_list.append(cookie_dict)
    return cookie_list

def simple_post_decode(string):
    post_dict = {}
    for i in string.split("&"): 
        k,v = i.replace("+", " ").split("=") 
        post_dict[url_unescape(k)] = url_unescape(v)
    return post_dict

def complex_post_decode(string, boundary):
    post_dict = {} 
    bc = bend.rfind("--%s--\r\n" % boundary)
    if bc < 0:
        raise Exception("no boundary end") 
    #skip boundary end
    for i in string[:bc].split("--%s\r\n" % boundary)[1:]:     
        header, content = i.split(HEADER_END) 
        kv = header.split("; ")
        if "Content-Disposition" not in kv[0]:
            raise Exception("no Content-Disposition")
        k = kv[1].split("=")[1] 
        #content header
        post_dict[k] = { 
                "content": content
                } 
        #form name
        if len(kv) == 2: 
            #maybe Content-Type 
            if NEWLINE in kv[-1]: 
                ch = {}
                for j in kv[-1].split(NEWLINE):
                    chk, chv = j.split(": ")
                    ch[url_unescape(chk)] = url_unescape(chv.strip('"'))
                post_dict[k]["header"] = ch 
        #form file
        elif len(kv) == 3: 
            if NEWLINE in kv[2]: 
                ch = {}
                fn = kv[-1].split(NEWLINE)
                for j in fn[1:]:
                    chk, chv = j.split(": ")
                    ch[chk] = chv.strip('"')
                post_dict[k]["header"] = ch 
                post_dict[k]["filename"] = fn[0].split("=")[1].strip('"')
    return post_dict 

def header_encode(header, client_side=True): 
    buf = StringIO()
    if client_side:
        buf.write(header["METHOD"])
        buf.write(header["PATH"])
        buf.write(" "+HTTP_VERSION) 
        buf.write(NEWLINE)
        del header["METHOD"]
        del header["PATH"]
    else: 
        buf.write(HTTP_VERSION+" ")
        buf.write(http_message[header["STATUS"]])
        buf.write(NEWLINE)
        del header["STATUS"] 
    for k,v in header.items():
        buf.write('%s: %s%s' % (k, v, NEWLINE)) 
    final = buf.getvalue()
    buf.close()
    return final 

def header_decode(header_string, client_side=True): 
    header_dict = {}
    cookie = None 
    #status line 
    first_line = header_string.find(NEWLINE) 
    status = header_string[:first_line].split(" ") 
    if client_side: 
        header_dict["PROTOCOL"] = status[0]
        header_dict["STATUS"] = int(status[1])
        header_dict["MESSAGE"] = " ".join(status[2:])
    else:
        header_dict["METHOD"] = status[0] 
        header_dict["PATH"] = status[1] 
    set_cookie_maybe = False
    if header_string[first_line+2:].find(NEWLINE) < 0:
        return header_dict, None
    for line in header_string[first_line+2:].split(NEWLINE): 
        kv = [x.strip() for x in line.split(":")] 
        #maybe multiple lines in Set-Cookie
        #bad luck if : in Set-Cookie
        if len(kv) == 1 and set_cookie_maybe:
            header_dict[SET_COOKIE] += "%s%s" % (NEWLINE, kv) 
            continue
        #maybe : in value
        if len(kv) > 2:
            kv[1] = ":".join(kv[1:]) 
        set_cookie_maybe = False
        #merge multiple Set-Cookie
        if kv[0] == SET_COOKIE:
            set_cookie_maybe = True 
            if SET_COOKIE in header_dict:
                header_dict[SET_COOKIE] += "%s%s" % (NEWLINE, kv[1])
            else:
                header_dict[SET_COOKIE] = kv[1]
            continue
        #merge multiple Cookie
        if kv[0] == COOKIE:
            if COOKIE in header_dict:
                header_dict[COOKIE] += "; %s" % kv[1]
            else:
                header_dict[COOKIE] = kv[1]
            continue
        header_dict[kv[0]] = kv[1]
    if SET_COOKIE in header_dict:
        cookie = server_cookie_decode(header_dict[SET_COOKIE])
    if COOKIE in header_dict:
        cookie = client_cookie_decode(header_dict[COOKIE])
    return header_dict, cookie
