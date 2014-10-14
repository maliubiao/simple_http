#-*-encoding=utf-8-*- 
import os.path 
import socket
import io 
import zlib
import pdb 
import signal
import base64
import json
import time
import errno
import string
import cStringIO

from uuid import uuid4
from struct import pack, unpack 
from collections import OrderedDict 

try:
    import ssl
    has_ssl = True
except:
    has_ssl = False

convert_table = [0 for x in range(256)]

#url reversed characters 
reversed_table = { 
        "\x21": "%21", #!
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

#使用0x0 - xff数组优化查找
for k,v in reversed_table.items():
    convert_table[ord(k)] = v 

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

#使用0x0 - 0xff数组优化查找
for k,v in common_chars_table.items():
    convert_table[ord(k)] = v

#是否是字符
letters = [0 for x in range(256)]
for x in string.letters:
    letters[ord(x)] = 1 


default_header = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3", 
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/32.0"
        } 

download_header = {
        "Accept": "*/*",
        "Connection": "Keep-Alive"
        }

#common mimetypes
common_types = {
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
resp_codes = {
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
        421: "421 There are too many remotes from your Internet Address",
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


default_timeout = 5

HTTP_VERSION = "HTTP/1.1"
HEADER_END = "\x0d\x0a\x0d\x0a" 
METHOD_GET = "GET "
METHOD_POST = "POST "
METHOD_DELETE = "DELETE "
METHOD_PUT = "PUT "
METHOD_OPTIONS = "OPTIONS "
METHOD_TRACE = "TRACE "
METHOD_HEAD = "HEAD " 

BOUNDARY = uuid4().hex
BOUNDARY_STRING = "--%s\r\n" % BOUNDARY
BOUNDARY_END = "--%s--" % BOUNDARY
FORM_FILE = 'Content-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n' 
FORM_STRING = 'Content-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' 
FORM_SIMPLE_TYPE = "application/x-www-form-urlencoded"
FORM_COMPLEX_TYPE = "multipart/form-data; boundary=%s" % BOUNDARY 


def basic_auth(user, password):
    if user and password:
        return "Basic %s" % base64.b64encode("%s:%s" % (user, password)) 
    if user:
        return "Basic %s" % base64.b64encode(user) 


def proxy_auth(proxy): 
    proxyd = urlparse(proxy) 
    if proxyd["scheme"] == "http": 
        return basic_auth(proxyd.get("user"), proxyd.get("password")) 


def get_scheme(urld): 
    use_ssl = False
    if "scheme" in urld:
        if urld["scheme"] == "https":
            use_ssl = True 
    if use_ssl:
        if not has_ssl: 
            raise socket.error("Unsupported scheme")
        port = 443 
    else:
        port = 80 
    return use_ssl, port


def generate_query(query): 
    ql = []
    for k, v in query.items():
        ql.append("%s=%s" % (quote_plus(k), quote_plus(v)))
    return "&".join(ql) 


def parse_query(query):
    qd = {}
    for q in query.split("&"):
        i = q.find("=")
        if i > -1:
            qd[unquote_plus(q[:i])] = unquote_plus(q[i+1:])
        else:
            qd[unquote_plus(q)] = None 
    return qd


def generate_simple_post(payload): 
    pl = []
    for k,v in payload.items():
        pl.append("%s=%s" % (quote_plus(k), quote_plus(v))) 
    return "&".join(pl)


def generate_complex_post(payload): 
    cl = []
    for k, v in payload.items():
        if isinstance(v, str):
            cl.append(BOUNDARY_STRING)
            cl.append(FORM_STRING % (k, v)) 
        if isinstance(v, file):
            filename = os.path.basename(v.name)
            if not filename:
                filename = "unknown" 
            cl.append(BOUNDARY_STRING)
            cl.append(FORM_FILE % (k, filename,
                                auto_content_type(filename))) 
            cl.append(v.read())
            cl.append("\r\n") 
        cl.append(BOUNDARY_END)
    return cl

def generate_post(header, payload): 
    has_file = False 
    #use multipart/form-data or not
    for k,v in payload.items(): 
        if isinstance(v, unicode):
            payload[k] = v.encode("utf-8")
        elif isinstance(v, file):
            has_file = True 
        elif isinstance(v, str):    
            continue
        else:
            raise Exception("payload value: str or unicode or fileobject") 
    if has_file: 
        header["Content-Type"] = FORM_COMPLEX_TYPE 
        return generate_complex_post(payload) 
    else:
        header["Content-Type"] = FORM_SIMPLE_TYPE 
        cl = generate_simple_post(payload) 
        return "".join(cl)


def quote(url): 
    result = [] 
    for char in url: 
        x = ord(char)
        if convert_table[x]:
            result.append(convert_table[x]) 
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
            ret.append(url[i+1:i+3].decode("hex")) 
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
    dot_offset = name.rfind(".") 
    if dot_offset < 0:
        return common_types["default"] 
    else:
        return common_types.get(name[dot_offset+1:], common_types["default"]) 


def generate_url(urldict):
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
        _append("#")
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
    _letters = letters 
    for i, c in enumerate(url): 
        #not enough
        if i < mark:
            continue

        #optimization for letters
        if _letters[ord(c)]:
            continue
        
        #handle delimiters
        if c == ":":                   
            if status >= 5:
                continue
            if url.find("://") == i:
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
    if status == 0:
        result["host"] = url
    else:
        if mark < len(url):
            result[remain] = url[mark:]
    result.setdefault("path", "/")
    return result        


def client_cookie(setcookie):
    ret = {}
    for cookie in setcookie:
        key, value = cookie["cookie"].split("=")
        ret[key] = value 
    return ret


def generate_cookie(simple_cookie_dict):
    ret = []
    has_unicode = False
    for k,v in simple_cookie_dict.items():
        if isinstance(k, unicode) or isinstance(v, unicode):
            has_unicode = True
        ret.append("%s=%s; " % (k,v)) 
    if has_unicode:
        return "".join(ret)[:-2].encode("utf-8")
    else:
        return "".join(ret)[:-2]


def parse_cookie(simple_cookie): 
    cookie_dict = {} 
    for cookie in simple_cookie.split(";"):
        kv = cookie.split("=")
        cookie_dict[kv[0].strip()] = kv[1].strip()
    return cookie_dict


def generate_setcookie(cookie_list):
    ret = []
    for cookie_dict in cookie_list:
        items_list = []
        for k,v in cookie_dict.items():
            if k == "cookie":
                item_list.append('%s; ' % v)
            else:    
                item_list.append('%s=%s; ' % (k, v))
        ret.append("".join(items_list)[:-2])
        ret.append("\r\n") 
    return "".join(ret)[:-2]


def parse_setcookie(string):
    cookie_list = [] 
    for line in string.split("\r\n"):
        cookie = {}
        lines = line.split(";")
        cookie["cookie"] = lines[0]
        for part in lines[1:]: 
            kv = part.split("=")
            #path=/ or httponly
            if len(kv) == 2 : 
                cookie[kv[0]] = kv[1]
            else: 
                cookie[kv[0]] = True
        cookie_list.append(cookie)
    return cookie_list


def parse_simple_post(string):
    post_dict = {}
    for i in string.split("&"): 
        k,v = i.replace("+", " ").split("=") 
        post_dict[unquote_plus(k)] = unquote_plus(v)
    return post_dict


#fix this
def parse_complex_post(string, boundary):
    post_dict = {} 
    boundary_end = string.rfind("--%s--\r\n" % boundary)
    if boundary_end < 0:
        raise Exception("no boundary end") 
    #skip boundary end
    for item in string[:boundary_end].split("--%s\r\n" % boundary)[1:]:     
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


def generate_client_header(header, method, path): 
    status_line = "".join((method,
        path,
        " ",
        HTTP_VERSION,
        "\r\n")) 
    body = "".join(["".join((k, ": ", v, "\r\n")) for k, v in header.items()]) 
    return "".join((status_line, body))


def generate_server_header(header, status):
    status_line = "".join((HTTP_VERSION,
        " ",
        resp_codes["status"],
        "\r\n")) 
    body = "".join(["".join((k, ": ", v, "\r\n")) for k, v in header.items()]) 
    return "".join((status_line, body)) 


def parse_client_header(string):
    parts = string.split("\r\n")
    status = parts[0].split(" ") 
    status_dict = {}
    status_dict["method"] = status[0] 
    status_dict["path"] = status[1] 
    status_dict["protocol"] = status[-1] 
    header = {}
    last = None
    for line in parts[1:]: 
        kv = [x.strip() for x in line.split(":")] 
        #maybe : in value
        if len(kv) > 2:
            kv[1] = ":".join(kv[1:]) 
        #maybe multiple lines
        if len(kv) == 1: 
            header[last[0]] += "\r\n" + kv
            continue
        last = kv
        header[kv[0]] = kv[1] 
    header.update(status_dict) 
    if "Cookie" in header:
        header["Cookie"] = parse_cookie(header["Cookie"]) 
    return header


def parse_server_header(string):    
    parts = string.split("\r\n")
    status = parts[0].split(" ") 
    status_dict = {} 
    status_dict["protocol"] = status[0] 
    status_dict["status"] = int(status[1]) 
    status_dict["message"] = " ".join(status[2:]) 
    header = {}
    last = None 
    for line in parts[1:]: 
        kv = [x.strip() for x in line.split(":")] 
        #maybe : in value
        if len(kv) > 2:
            kv[1] = ":".join(kv[1:]) 
        #maybe multiple lines
        if len(kv) == 1: 
            header[last[0]] += "\r\n" + kv
            continue
        last = kv
        header[kv[0]] = kv[1] 
    header.update(status_dict) 
    if "Set-Cookie" in header:
        header["Set-Cookie"] = parse_setcookie(header["Set-Cookie"]) 
    if "Set-Cookie2" in header:
        header["Set-Cookie2"] = parse_setcookie(header["Set-Cookie2"]) 
    return header 

def get(url, **kwargs):
    return common_get(url, method=METHOD_GET, **kwargs)

def head(url, **kwargs):
    return common_get(url, method=METHOD_HEAD, header_only=True, **kwargs)

def delete(url, **kwargs):
    return common_get(url, method=METHOD_DELETE, **kwargs) 

def trace(url, **kwargs):
    return common_get(url, method=METHOD_TRACE, **kwargs)

def options(url, **kwargs):
    return common_get(url, method=METHOD_OPTIONS, **kwargs)


def common_get(url, **kwargs): 
    request_list = [] 
    urld = urlparse(url) 
    #http basic authorization 
    basicauth = basic_auth(urld.get("user"), urld.get("password")) 
    if "user" in urld:
        del urld["user"]
    if "password" in urld:        
        del urld["password"] 
    proxy = kwargs.get("proxy", "")
    if proxy:
        pauth = proxy_auth(proxy)
    else:
        pauth = None 
    #maybe ssl
    use_ssl, port = get_scheme(urld) 
    #handle query string
    if kwargs.get("query"):
        urld["query"] = generate_query(kwargs["query"]) 
    host = urld["host"] 
    #http proxy: remove scheme://host:port 
    if not pauth:
        del urld["host"] 
    if "scheme" in urld:
        del urld["scheme"] 
    if "port" in urld:
        port = int(urld["port"])
        del urld["port"] 
    if not kwargs.get("header"):
        header = default_header.copy() 
    else:
        header = kwargs["header"]
    header["Host"] = "%s:%d" % (host, port) 
    #reuqest path
    path = generate_url(urld) 
    method= kwargs.get("method", METHOD_GET) 
    #for basic authorization 
    if basicauth: header["Authorization"] = basicauth 
    #for basic proxy authorization
    if pauth: header["Proxy-Authorization"] = pauth
    request_list.append(generate_client_header(header, method, path)) 
    #generate cookie and HEADER_END
    if kwargs.get("cookie"):
        request_list.append("Cookie: ")    
        request_list.append(generate_cookie(kwargs["cookie"])) 
        request_list.append(HEADER_END) 
    else:
        request_list.append("\r\n") 
    #args for send_http
    body = "".join(request_list)       
    remote = (host, port) 
    return send_http(remote, use_ssl, body, 
            kwargs.get("timeout", default_timeout),
            proxy, kwargs.get("header_only", False))


def put(url, **kwargs):
    return general_post(url, method=METHOD_PUT, **kwargs)

def post(url, **kwargs):
    return general_post(url, method=METHOD_POST, **kwargs) 

def general_post(url, **kwargs): 
    request_list = []
    use_ssl = False 
    urld = urlparse(url) 
    #http basic authorization 
    basicauth =basic_auth(urld.get("user"), urld.get("password")) 
    if "user" in urld:
        del urld["user"]
    if "password" in urld:
        del urld["password"] 
    proxy = kwargs.get("proxy")
    if proxy:
        pauth = proxy_auth(proxy)
    else:
        pauth = None
    #generate path 
    use_ssl, port = get_scheme(urld) 
    proxy = kwargs.get("proxy")
    if not pauth:
        host = urld["host"]
        del urld["host"]
    if "scheme" in urld:
        del urld["scheme"]
    if "port" in urld: 
        port = int(urld["port"])
        del urld["port"] 
    path = generate_url(urld) 
    method= kwargs.get("method", METHOD_GET) 
    if "header" not in kwargs:
        header = default_header.copy() 
    else:
        header = kwargs["header"] 
    header["Host"] = "%s:%d" % (host, port) 
    content = generate_post(header, kwargs["payload"]) 
    header["Content-Length"] = str(len(content)) 
    #mangle header for basic authorization
    if basicauth: header["Authorization"] = basicauth 
    #mangle header for basic proxy authorization
    if pauth: header["Proxy-Authorization"] = pauth 
    request_list.append(generate_client_header(header, method, path)) 
    #generate cookie and HEADER_END
    if "cookie" in kwargs:
        request_list.append("Cookie: ")    
        request_list.append(generate_cookie(kwargs["cookie"])) 
        request_list.append(HEADER_END) 
    else:
        request_list.append("\r\n")
    request_list.append(content) 
    body = "".join(request_list)
    remote = (host, port) 
    return send_http(remote, use_ssl, body, 
            kwargs.get("timeout", default_timeout), proxy, False) 

def handle_chunked(cbuf, normal_stream): 
    end = cbuf.tell()
    cbuf.seek(0)
    goout = 0
    while True: 
        num = "" 
        while True: 
            char = cbuf.read(1) 
            if not char:
                goout = True
                break 
            if char == "\r": 
                break
            num += char 
        if goout:
            break
        cbuf.seek(1, io.SEEK_CUR)
        x = int(num, 16)
        if not x:
            break
        chunk = cbuf.read(x)
        cbuf.seek(2, io.SEEK_CUR)
        if len(chunk) != x:
            break
        normal_stream.write(chunk) 


def wait_header(data, hbuf): 
    hend = data.find(HEADER_END) 
    if hend < 0: 
        #slow network, wait for header 
        hbuf.write(data) 
        return None, None
    else:
        hbuf.write(data)
        data = hbuf.getvalue()
        hend = data.find(HEADER_END)
        hbuf.close() 
    header = parse_server_header(data[:hend]) 
    return header, data[hend+4:] 


def wait_response(remote, header_only=False):
    total_length = 0xffffffff 
    chunked = False 
    has_header = False 
    has_range = False 
    length_unkown = False 
    header = None 
    hbuf = cStringIO.StringIO()
    cbuf = cStringIO.StringIO() 
    while True: 
        try:
            data = remote.recv(40960) 
        except socket.error: 
            raise 
        #remote closed
        if not data:
            break 
        if not has_header: 
            header, data = wait_header(data, hbuf)
            #again
            if not header:
                continue 
            if header_only: 
                break
            if "Content-Length" in header:
                total_length = int(header["Content-Length"])
            else:
                length_unkown = True 
            #maybe chunked stream 
            if header.get("Transfer-Encoding") == "chunked": 
                chunked = True 
            if header.get("Accept-Ranges") == "bytes":
                has_range = True 
            if header.get("Content-Range"):
                length_unkown = False 
            has_header = True 
            if (not chunked and 
                not has_range and 
                length_unkown and
                not data and
                header["status"] == 200):
                #no idea how this stream ends, wait
                continue 
        cbuf.write(data) 
        #handle chunked data
        if chunked:
            chunked_end = data.rfind("0\r\n\r\n")
            if chunked_end > -1: 
                cbuf.getvalue() 
                normal = cStringIO.StringIO()
                handle_chunked(cbuf, normal) 
                cbuf.close() 
                return header, normal.getvalue()
        #if we don't know the end, assume HEADER_END
        if length_unkown and not chunked:
            entity_end = data.rfind(HEADER_END)
            if entity_end == (len(data) -4): 
                break 
        #Content-Length
        if cbuf.tell() >= total_length: 
            break 
        #no more data 
        if ((header.get("Connection") == "close" or
                header["status"] >= 300 or
                header["status"] < 200) and
                length_unkown and
                not chunked): 
            break 
    return header, cbuf.getvalue() 


def connect_sock5(sock, remote, server): 
    sock.connect(server) 
    #socks5 handshake
    sock.send("\x05\x01\x00") 
    if not sock.recv(4).startswith("\x05\x00"): 
        sock.close()
        raise socket.error("connect proxy failed") 
    #use remote dns by default
    hdr = "\x05\x01\x00\x03%s%s%s" % (pack("B",
        len(remote[0])), remote[0],
        pack(">H", remote[1]))
    sock.send(hdr) 
    #if request failed
    if not sock.recv(12).startswith("\x05\x00"): 
        sock.close()
        raise socket.error("proxy network error")


def connect_proxy(sock, remote, proxy): 
    proxy_type = None
    proxyd = urlparse(proxy)
    scheme = proxyd["scheme"]
    if scheme in "https": 
        proxy_type = "http"
        sock.connect((proxyd["host"], proxyd["port"])) 
    elif scheme == "socks5": 
        proxy_type = "socks5"
        connect_sock5(sock, remote, (proxyd["host"], int(proxyd["port"]))) 
    else:
        raise socket.error("unknown proxy type")
    return proxy_type 


def send_http(remote, use_ssl, message, timeout, proxy=None, header_only=False): 
    try: 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.settimeout(timeout)
        #if there is a proxy , connect proxy server instead 
        proxy_type = None 
        if proxy:
            proxy_type = connect_proxy(sock, remote, proxy)
        else:
            sock.connect(remote) 
        if use_ssl and proxy_type != "http":
            sock = ssl.wrap_socket(sock) 
        sock.send(message) 
        header, body = wait_response(sock, header_only)
    except socket.error:
        sock.close() 
        raise 
    #handle compressed stream: gzip, deflate 
    if not header_only and header: 
        #maybe gzip stream
        if header.get("Content-Encoding") == "gzip": 
            body = zlib.decompress(body, 16+zlib.MAX_WBITS)  
        elif header.get("Content-Encoding") == "deflate":
            body = zlib.decompress(body, -zlib.MAX_WBITS)  
    return header, body 
