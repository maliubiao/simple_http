"""
simple http library 
"""


import os.path 
import socket
import io 
import zlib
import pdb 
import signal
import base64
import json
import time

from string import letters 
from uuid import uuid4
from struct import pack, unpack
from cStringIO import StringIO 
from collections import OrderedDict 

try:
    import ssl
    has_ssl = True
except:
    has_ssl = False


#url reversed characters 
reversed_table = { 
        #0x21: "%21", #!
        "\x23": "%23", ##
        "\x24": "%24", #$
        "\x26": "%26", #&
        #0x27: "%27", #'
        #0x28: "%28", #(
        #0x29: "%29", #)
        "\x2A": "%2A", #*
        "\x2B": "%2B", #+
        "\x2C": "%2C", #,
        "\x2F": "%2F", #/
        "\x3A": "%3A", #:
        "\x3B": "%3B", #;
        "\x3D": "%3D", #=
        "\x3F": "%3F", #?
        "\x40": "%40", #@
        #0x5B: "%5B", #[
        #0x5D: "%5D" #]
        }

#url common characters
common_chars_table = {
        "\x20": "%20", #space
        "\x22": "%22", #"
        "\x25": "%25", #%
        "\x2D": "%2D", #-
        #0x2E: "%2E", #.
        "\x3C": "%3C", #<
        "\x3E": "%3E", #>
        "\x5C": "%5C", #\
        "\x5E": "%5E", #^
        #0x5F: "%5F", #_                
        "\x60": "%60", #`
        "\x7B": "%7B", #{
        "\x7C": "%7C", #|
        "\x7D": "%7D", #}
        "\x7E": "%7E" #~
        }



default_header = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3", 
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/25.0"
        } 

#common mimetypes
commts = {
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
responses = {
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
METHOD_GET = "GET "
METHOD_POST = "POST "
METHOD_DELETE = "DELETE "


BOUNDARY = uuid4().hex
BOUNDARY_STRING = "--%s\r\n" % BOUNDARY
BOUNDARY_END = "--%s--" % BOUNDARY
FORM_FILE = 'Content-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n' 
FORM_STRING = 'Content-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' 
FORM_SIMPLE_TYPE = "application/x-www-form-urlencoded"
FORM_COMPLEX_TYPE = "multipart/form-data; boundary=%s" % BOUNDARY 



#ascii -> %hex
_hextochr = {} 
#%hex -> ascii
_chrtohex = {}        

_hextochr = dict(("%%%X" % char, chr(char))
        for char in range(0x0, 0xff+1))
_chrtohex = dict((chr(char), "%%%X" % char)
        for char in range(0x0, 0xff+1)) 


def basic_auth_from_url(url_dict): 
    if "password" in url_dict: 
        basicauth = "Basic %s" % base64.b64encode("%s:%s" % (url_dict["user"], url_dict["password"])) 
        del url_dict["password"]
    else:
        basicauth = "Basic %s" % base64.b64encode(url_dict["user"])
    del url_dict["user"]
    return basicauth

def proxy_from_url(proxy): 
    proxy_dict = urlparse(proxy) 
    if proxy_dict["scheme"] == "http":
        if proxy_dict.get("user"):
            http_proxy = "Basic %s" % base64.b64encode("%s:%s" % (proxy_dict["user"], proxy_dict["password"])) 
    else:
        http_proxy = "" 
    return http_proxy

def join_query_dict(query):
    return "?%s" % ("&".join(["=".join((quote_plus(k), quote_plus(v))) for k,v in query.items()]))


def scheme_from_dict(url_dict): 
    use_ssl = False
    if "scheme" in url_dict:
        if url_dict["scheme"] == "https":
            use_ssl = True 
    if use_ssl:
        if not has_ssl: 
            raise Exception("Unsupported scheme")
        port = 443 
    else:
        port = 80 
    return use_ssl, port


def get(url, **kwargs):
    return general_get(url, httpmethod="GET ", **kwargs)


def general_get(url, **kwargs): 
    request_list = [] 
    url_dict = urlparse(url) 
    #http basic authorization 
    basicauth = None 
    if "user" in url_dict:
        basicauth = basic_auth_from_url(url_dict) 
    #http proxy, mangle header
    http_proxy = None
    if kwargs.get("proxy"):
        http_proxy = proxy_from_url(kwargs["proxy"])
    else:
        kwargs["proxy"] = ""
    #maybe ssl connection
    use_ssl, port = scheme_from_dict(url_dict) 
    #handle query string
    if kwargs.get("query"):
        url_dict["query"] = join_query_dict(kwargs["query"]) 
    host = url_dict["host"] 
    #remove scheme://host:port 
    if not http_proxy:
        del url_dict["host"] 
    if "scheme" in url_dict:
        del url_dict["scheme"] 
    if "port" in url_dict:
        port = int(url_dict["port"])
        del url_dict["port"] 
    if not kwargs.get("header"):
        header = default_header.copy() 
    else:
        header = kwargs["header"]
    header["Host"] = "%s:%d" % (host, port) 
    #reuqest path
    path = urlunparse(url_dict) 
    if kwargs.get("httpmethod"):
        header["method"] = kwargs["httpmethod"] 
    header["path"] = path 
    #for basic authorization 
    if basicauth: header["Authorization"] = basicauth 
    #for basic proxy authorization
    if http_proxy: header["Proxy-Authorization"] = http_proxy 
    request_list.append(unparse_header(header)) 
    #generate cookie and HEADER_END
    if kwargs.get("cookie"):
        request_list.append("Cookie: ")    
        request_list.append(unparse_simple_cookie(kwargs["cookie"])) 
        request_list.append(HEADER_END) 
    else:
        request_list.append("\r\n") 
    if not kwargs.get("timeout"):
        kwargs["timeout"] = 0 
    #args for send_http
    final = "".join(request_list)       
    connection = (host, port) 
    args = (connection, use_ssl, final, kwargs["proxy"],  kwargs["timeout"])
    return send_http(*args)

def handle_chunked(data, normal_stream):
    prev_chunk = 0
    next_chunk = 0
    this_chunk = 0 
    while True:
        next_chunk = data.find("\r\n", prev_chunk)
        if next_chunk < 0: return
        try:
            this_chunk = int(data[prev_chunk:next_chunk], 16)
        except: 
            raise socket.error("chunked error")
        next_chunk += 2
        if not this_chunk: return
        normal_stream.write(data[next_chunk: next_chunk+this_chunk])
        prev_chunk = next_chunk + this_chunk + 2

def wait_response(connection, normal_stream, timeout=0):
    total_length = 0xffffffff 
    chunked = False 
    length_unkown = False 
    header = None 
    cookie = None
    has_header = False 
    header_buffer = StringIO()
    content_buffer = StringIO()
    has_range = False 

    #if recv blocks, interrupt syscall after timeout
    if timeout:
        signal.alarm(timeout) 
        def wait_timeout(signum, frame):
            return
        signal.signal(signal.SIGALRM, wait_timeout) 

    while True: 
        try:
            data = connection.recv(40960) 
        #interrupted syscall
        except socket.error as err: 
            raise err 

        if has_header and not data:
            break 
        
        if not has_header: 
            header_end = data.find(HEADER_END) 
            if header_end < 0: 
                #slow network, wait for header 
                header_buffer.write(data)
                continue
            else:
                header_buffer.write(data)
                data = header_buffer.getvalue()
                header_end = data.find(HEADER_END)
                header_buffer.close() 
            header, cookie = parse_header(data[:header_end]) 
            if "Content-Length" in header:
                total_length = int(header["Content-Length"])
            else:
                length_unkown = True 
            #maybe chunked stream
            if header.get("Transfer-Encoding") == "chunked": 
                chunked = True 
            if header.get("Accept-Ranges") == "bytes":
                has_range = True
                length_unkown = True
            if header.get("Content-Range"):
                length_unkown = False 

            data = data[header_end+4:] 
            if not chunked and not has_range and length_unkown and not data:
                #no idea how this stream ends, wait 0.1 seconds
                time.sleep(0.1)
            has_header = True 

        content_buffer.write(data) 
        #handle chunked data
        if chunked:
            chunked_end = data.rfind("0\r\n\r\n")
            if chunked_end > -1: 
                handle_chunked(content_buffer.getvalue(), normal_stream)
                content_buffer.close()
                return header, cookie
        #if we don't know the end, assume HEADER_END
        if length_unkown and not chunked:
            entity_end = data.rfind(HEADER_END)
            if entity_end == (len(data) -4): 
                break 
        #Content-Length
        if content_buffer.tell() >= total_length:
            break; 
        #no more data
        if header.get("Connection") == "close" and length_unkown and not chunked:
            break 
    normal_stream.write(content_buffer.getvalue())
    content_buffer.close()
    return header, cookie

def connect_proxy(sock, connection, proxy): 
    proxy_type = None
    proxy_dict = urlparse(proxy)
    if proxy_dict["scheme"] == "socks5":
        proxy_type = "socks5"
        proxy_server = (proxy_dict["host"], int(proxy_dict["port"])) 
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
    return proxy_type


def send_http(connection, use_ssl, message, proxy=None, timeout=0): 
    try: 
        content_buffer = StringIO() 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        #if there is a proxy , connect proxy server instead
        proxy_type = None 
        if proxy:
            proxy_type = connect_proxy(sock, connection, proxy)
        else:
            sock.connect(connection)
        if use_ssl and proxy_type != "http":
            sock = ssl.wrap_socket(sock) 
        sock.send(message) 
        header, cookie = wait_response(sock,
                content_buffer,
                timeout=timeout)
    except socket.error, err: 
        content_buffer.close()
        sock.close()
        raise err 

    sock.close() 
    #handle compressed stream: gzip, deflate 
    try: 
        #maybe gzip stream
        if header.get("Content-Encoding") == "gzip": 
            final = zlib.decompress(content_buffer.getvalue(),
                    16+zlib.MAX_WBITS)  
        elif header.get("Content-Encoding") == "deflate":
            final = zlib.decompress(content_buffer.getvalue(),
                    -zlib.MAX_WBITS)  
        else:
            final = content_buffer.getvalue() 
    except Exception as e: 
        raise e
    content_buffer.close() 
    return header, cookie, final


def unparse_post(header, payload): 
    has_file = False 
    content_list = []
    #use multipart/form-data or not
    for k,v in payload.items(): 
        if not (isinstance(v, str) or isinstance(v, file)): 
            raise Exception("payload value: str or unicode or fileobject")
        if isinstance(v, file):
            has_file = True 

    #generate multipart stream
    if has_file: 
        for k, v in payload.items():
            if isinstance(v, str):
                content_list.append(BOUNDARY_STRING)
                content_list.append(FORM_STRING % (k, v)) 
            if isinstance(v, file):
                filename = os.path.basename(v.name)
                if not filename:
                    filename = "unknown" 
                content_list.append(BOUNDARY_STRING)
                content_list.append(FORM_FILE % (k, filename,
                                    auto_content_type(filename))) 
                content_list.append(v.read())
                content_list.append("\r\n") 
        content_list.append(BOUNDARY_END)
        header["Content-Type"] = FORM_COMPLEX_TYPE 
    else:
        content_list.append("&".join(["=".join((quote_plus(k),
                            quote_plus(v))) for k, v in payload.items()])) 
        header["Content-Type"] = FORM_SIMPLE_TYPE 

    return "".join(content_list)

def post(url, **kwargs): 
    request_list = []
    use_ssl = False 
    url_dict = urlparse(url) 
    #http basic authorization
    basicauth = None
    if "user" in url_dict:
        basicauth = basic_auth_from_url(url_dict) 
    #http proxy, mangle header
    http_proxy = None
    if kwargs.get("proxy"):
        http_proxy = proxy_from_url(kwargs["proxy"])
    else:
        kwargs["proxy"] = ""

    #generate path 
    use_ssl, port = scheme_from_dict(url_dict) 
    if not http_proxy:
        host = url_dict["host"]
        del url_dict["host"]
    if "scheme" in url_dict:
        del url_dict["scheme"]
    if "port" in url_dict: 
        port = int(url_dict["port"])
        del url_dict["port"] 
    path = urlunparse(url_dict) 

    if "header" not in kwargs:
        header = default_header.copy() 
    else:
        header = kwargs["header"]

    header["Host"] = "%s:%d" % (host, port) 
    content = unparse_post(header, kwargs["payload"]) 
    header["Content-Length"] = str(len(content))
    header["path"]  = path
    header["method"] = METHOD_POST
    #mangle header for basic authorization
    if basicauth: header["Authorization"] = basicauth 
    #mangle header for basic proxy authorization
    if http_proxy: header["Proxy-Authorization"] = http_proxy 
    request_list.append(unparse_header(header)) 
    #generate cookie and HEADER_END
    if "cookie" in kwargs:
        request_list.append("Cookie: ")    
        request_list.append(unparse_simple_cookie(kwargs["cookie"])) 
        request_list.append(HEADER_END)
    else:
        request_list.append("\r\n")
    request_list.append(content) 
    kwargs.setdefault("timeout", 0) 
    #args
    final = "".join(request_list)
    connection = (host, port) 
    return send_http(connection, use_ssl, final, kwargs["proxy"], kwargs["timeout"]) 


def quote(url): 
    result = [] 
    for char in url: 
        if char in reversed_table:
            result.append(reversed_table[char]) 
        elif char in common_chars_table:
            result.append(common_chars_table[char]) 
        else: 
            result.append(char) 
    return "".join(result)

def unquote(url): 
    ret = []
    i = 0
    ulen = len(url)
    while i < ulen:
        char = url[i]
        if char == "%": 
            ret.append(_hextochr[url[i:i+3]]) 
            i = i+ 3
        else:
            ret.append(char)
            i += 1 
    return "".join(ret) 

def quote_plus(url): 
    if ' ' in url:
        return quote(url.replace(' ', '+')) 
    return quote(url)

def unquote_plus(url):
    url = url.replace("+", " ") 
    return unquote(url) 

def auto_content_type(name):
    dot_offset = name.find(".") 
    if dot_offset < 0:
        return commts["default"] 
    else:
        return commts.get(name[dot_offset+1:], commts["default"]) 


def urlunparse(urldict):
    result = []
    _append = result.append
    if "scheme" in urldict: 
        _append(urldict["scheme"] + "://") 
    if "user" in urldict:
        _append(urldict["user"]) 
        if "password" in urldict: 
            result.append(":" + urldict["password"]) 
        _append("@") 
    if "host" in urldict: 
        _append(urldict["host"]) 
    if "port" in urldict: 
        _append(":" + str(port)) 
    if "path" in urldict: 
        if not urldict["path"].startswith("/"):
            result.append("/") 
        _append(urldict["path"]) 
    if "query" in urldict: 
        _append("?" + urldict["query"]) 
    if "params" in urldict: 
        _append(";" + ";".join(urldict["params"])) 
    if "fragment" in urldict:  
        _append(urldict["fragment"]) 
    return "".join(result)

def urlparse(url): 
    """
    status = 0, scheme
    status = 1, user
    status = 2, password
    status = 3, host
    status = 4, port
    status = 5, path
    status = 6, params,
    status = 7, query
    status = 8, frag
    status = 9, end
    """
    result = {} 
    status = 0
    mark = 0
    remain = None 
    for i, c in enumerate(url): 
        #not enough
        if i < mark:
            continue

        #optimization for letters
        if c in letters:
            continue
        
        #handle delimiters
        if c == ":":                   
            if url[i: i+3] == "://":
                status = 1
                result["scheme"] =  url[:i]
                mark = i + 2 
                remain = "host" 
            else: 
                #host:port
                if url[i+1].isdigit():
                    #next port
                    result["host"] = url[mark:i] 
                    status = 4 
                    remain = "port"
                #user
                else: 
                    result["user"] = url[mark:i]  
                    #next password
                    status = 2 
                    remain = "password"

        elif c == "/": 
            if status >= 5: 
                continue
            #host:port, for port
            if status in (0, 1, 3):
                result["host"] = url[mark:i]   
            if status == 4:
                result["port"] = url[mark:i] 
            #next possible "path"
            remain = "path"    
            status = 5 
        elif c == "@": 
            if status != 2:
                #user@host
                result["user"] = url[mark:i] 
            #user:password@host
            else:
                result["password"] = url[mark:i] 
            #next possible "host"
            remain = "host"
            status = 3 

        elif c in ";?#":
            #path
            if status == 5:
                result["path"] = url[mark:i] 
                status = 6 
            #params
            elif status == 6:
                result["params"] = url[mark:i] 
                status = 7
            #query
            elif status == 7:
                result["query"] = url[mark:i] 
                status = 8
            #frag
            elif status == 8: 
                result["fragment"] = url[mark:i] 
                status = 9 
        #skip normal char
        else: 
            continue

        if c == ";":
            #next params 
            remain = "params"
            status = 6

        elif c == "?":
            #next query
            remain = "query"
            status = 7

        elif c == "#":
            remain = "fragment"
            status = 8 

        if mark < i:
            mark = i + 1
        else:
            mark += 1
    #host.com 
    if not status:
        result["host"] = url
    else:
        if mark < len(url):
            result[remain] = url[mark:]
    result.setdefault("path", "/")
    return result        

def cookie_full_to_simple(full_cookie):
    ret = {}
    for cookie in full_cookie:
        key, value = cookie["cookie"].split("=")
        ret[key] = value 
    return ret

def unparse_simple_cookie(simple_cookie_dict):
    ret = []
    for k,v in simple_cookie_dict.items():
        ret.append("%s=%s; " % (k,v))
    return "".join(ret)[:-2]

def parse_simple_cookie(simple_cookie): 
    cookie_dict = {} 
    for cookie in simple_cookie.split(";"):
        kv = cookie.split("=")
        cookie_dict[kv[0].strip()] = kv[1].strip()
    return cookie_dict

def unparse_full_cookie(cookie_list):
    ret = []
    for cookie_dict in cookie_list:
        items_list = []
        for k,v in cookie_dict.items():
            if k == "cookie":
                item_list.append('%s; ' % v)
                continue
            item_list.append('%s=%s; ' % (k, v))
        ret.append("".join(items_list)[:-2])
        ret.append("\r\n") 
    return "".join(ret)[:-2]

def parse_full_cookie(cookie):
    cookie_list = [] 
    for line in cookie.split("\r\n"):
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

def parse_simple_post(string):
    post_dict = {}
    for i in string.split("&"): 
        k,v = i.replace("+", " ").split("=") 
        post_dict[unquote_plus(k)] = unquote_plus(v)
    return post_dict

def parse_complex_post(string, boundary):
    post_dict = {} 
    bc = bend.rfind("--%s--\r\n" % boundary)
    if bc < 0:
        raise Exception("no boundary end") 
    #skip boundary end
    for item in string[:bc].split("--%s\r\n" % boundary)[1:]:     
        header, content = item.split(HEADER_END) 
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
            if "\r\n" in kv[-1]: 
                ch = {}
                for j in kv[-1].split("\r\n"):
                    chk, chv = j.split(": ")
                    ch[unquote_plus(chk)] = unquote_plus(chv.strip('"'))
                post_dict[k]["header"] = ch 
        #form file
        elif len(kv) == 3: 
            if "\r\n" in kv[2]: 
                ch = {}
                fn = kv[-1].split("\r\n")
                for j in fn[1:]:
                    chk, chv = j.split(": ")
                    ch[chk] = chv.strip('"')
                post_dict[k]["header"] = ch 
                post_dict[k]["filename"] = fn[0].split("=")[1].strip('"')
    return post_dict 

def unparse_header(header, client_side=True): 
    if client_side:
        status_line = "".join((header["method"], header["path"], " ", HTTP_VERSION, "\r\n")) 
        del header["method"]
        del header["path"]
    else: 
        status_line = "".join((HTTP_VERSION, " ", responses[header["status"]], "\r\n")) 
        del header["status"] 
    body = "".join(["".join((k, ": ", v, "\r\n")) for k, v in header.items()]) 
    return "".join((status_line, body))


def parse_header(header_string): 
    #status line 
    server_side = True
    parts = header_string.split("\r\n")
    status = parts[0].split(" ") 
    status_dict = {}
    if status[0].startswith("HTTP/1"): 
        status_dict["protocol"] = status[0] 
        status_dict["status"] = int(status[1]) 
        status_dict["message"] = " ".join(status[2:])
    else:
        server_side = False
        status_dict["method"] = status[0] 
        status_dict["path"] = status[1] 
        status_dict["protocol"] = status[-1] 
    #[(k, v), (k, v)]
    header_list = [] 
    for line in parts[1:]: 
        kv = [x.strip() for x in line.split(":")] 
        #maybe : in value
        if len(kv) > 2:
            kv[1] = ":".join(kv[1:]) 
        #maybe multiple lines
        if len(kv) == 1: 
            header_list[-1][1] += "".join(("\r\n", kv)) 
            continue
        header_list.append((kv[0], kv[1]))

    header_dict = dict(header_list) 
    header_dict.update(status_dict)
    cookie = "" 
    for item in header_list:
        if item[0].startswith("Set-Cookie"):
            if cookie:            
                cookie += "".join(("\r\n", item[1]))
            else:
                cookie = item[1] 
                del header_dict[item[0]]   
        if item[0] == "Cookie":
            if cookie:
                cookie += "".join(("; ", item[1]))
            else:
                cookie = item[1] 
                del header_dict[item[0]]

    if not cookie:
        return header_dict, None

    if server_side:
        cookie = parse_full_cookie(cookie) 
    else:
        cookie = parse_simple_cookie(cookie)
    return header_dict, cookie
