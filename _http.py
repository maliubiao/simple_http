# -*-encoding=utf-8-*-
import os.path
import base64
import string 

from uuid import uuid4

try:
    import ssl

    has_ssl = True
except:
    has_ssl = False

convert_table = [0 for x in range(256)]

# url reversed characters
reversed_table = {
    "\x21": "%21",  # !
    "\x23": "%23",  ##
    "\x24": "%24",  # $
    "\x26": "%26",  # &
    "\x27": "%27",  # '
    "\x28": "%28",  # (
    "\x29": "%29",  # )
    "\x2A": "%2A",  # *
    "\x2B": "%2B",  # +
    "\x2C": "%2C",  # ,
    "\x2F": "%2F",  # /
    "\x3A": "%3A",  #:
    "\x3B": "%3B",  # ;
    "\x3D": "%3D",  # =
    "\x3F": "%3F",  # ?
    "\x40": "%40",  # @
    "\x5B": "%5B",  # [
    "\x5D": "%5D"  # ]
}

# 使用0x0 - xff数组优化查找
for k, v in reversed_table.items():
    convert_table[ord(k)] = v

# url common characters
common_chars_table = {
    "\x20": "%20",  # space
    "\x22": "%22",  # "
    "\x25": "%25",  # %
    # "\x2D": "%2D", #-
    # 0x2E: "%2E", #.
    "\x3C": "%3C",  # <
    "\x3E": "%3E",  # >
    "\x5C": "%5C",  # \
    "\x5E": "%5E",  # ^
    # 0x5F: "%5F", #_
    "\x60": "%60",  # `
    "\x7B": "%7B",  # {
    "\x7C": "%7C",  # |
    "\x7D": "%7D",  # }
    "\x7E": "%7E"  # ~
}

# 使用0x0 - 0xff数组优化查找
for k, v in common_chars_table.items():
    convert_table[ord(k)] = v

# 是否是字符
letters = [0 for x in range(256)]
for x in string.letters:
    letters[ord(x)] = 1

hex_digits_set = set(string.hexdigits)

default_header = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    # "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3",
    "Connection": "keep-alive",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36"
}

download_header = { 
    "Accept": "*/*", 
    "Connection": "Keep-Alive"
}

image_header = {
    "Accept": "*/*", 
    "Accept-Encoding": "gzip, deflate",
    "Connection": "Keep-Alive",
}


html_header = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
}

json_header = {
    "Accept": "application/json,text/javascript,*/*;q=0.01",
    "Accept-Language": "zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3",
    "Connection": "keep-alive", 
    "Content-Type": "application/x-www-form-urlencoded", 
    "Cache-Control": "no-cache",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "X-Requested-With": "XMLHttpRequest"
}



# common mimetypes
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


# http consts
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

default_timeout = 30

HTTP_VERSION = "HTTP/1.1"
HEADER_END = "\x0d\x0a\x0d\x0a"
HEADER_END2 = "\n\n"
METHOD_GET = "GET"
METHOD_POST = "POST"
METHOD_DELETE = "DELETE"
METHOD_PUT = "PUT"
METHOD_OPTIONS = "OPTIONS"
METHOD_TRACE = "TRACE"
METHOD_HEAD = "HEAD"


def set_boundary(uid):
    g = globals()
    g["BOUNDARY"] = uid
    g["BOUNDARY_STRING"] = "--%s\r\n" % BOUNDARY
    g["BOUNDARY_END"] = "--%s--" % BOUNDARY
    g["FORM_FILE"] = 'Content-Disposition: form-data; name="%s"; filename="%s"\r\nContent-Type: %s\r\n\r\n'
    g["FORM_STRING"] = 'Content-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
    g["FORM_SIMPLE_TYPE"] = "application/x-www-form-urlencoded"
    g["FORM_COMPLEX_TYPE"] = "multipart/form-data; boundary=%s" % BOUNDARY


set_boundary(uuid4().hex)


def basic_auth_msg(user, password):
    if user and password:
        return "Basic %s" % base64.b64encode("%s:%s" % (user, password))
    if user:
        return "Basic %s" % base64.b64encode(user)


def proxy_auth_msg(proxy):
    proxyd = urlparse(proxy)
    if proxyd["schema"] == "http":
        return basic_auth_msg(proxyd.get("user"), proxyd.get("password"))


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
            qd[unquote_plus(q[:i])] = unquote_plus(q[i + 1:])
        else:
            qd[unquote_plus(q)] = None
    return qd


def generate_simple_post(payload):
    pl = []
    for k, v in payload.items():
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
    if isinstance(payload, str):
        return payload
    elif isinstance(payload, unicode): 
        return payload.encode("utf-8") 
    elif isinstance(payload, dict):
        has_file = False
        # use multipart/form-data or not
        for k, v in payload.items():
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
            return "".join(generate_complex_post(payload))
        else:
            header["Content-Type"] = FORM_SIMPLE_TYPE
            cl = generate_simple_post(payload)
            return "".join(cl)
    else:
        raise ValueError("unknown payload type: %s" % type(payload))


def quote(url): 
    result = []
    for char in url.decode("utf-8"): 
        x = ord(char)
        if x < 256:
            if convert_table[x]:
                result.append(convert_table[x])
            else:
                result.append(char)
        else:
            result.extend(["%" + i.encode("hex").upper() for i in char.encode("utf-8")]) 
    return "".join(result)


# fix bug
def unquote(url):
    ret = []
    i = 0
    ulen = len(url)
    if not ulen:
        return url
    while i < ulen:
        char = url[i]
        if char == "%":
            ret.append(url[i + 1:i + 3].decode("hex"))
            i = i + 3
        else:
            ret.append(char)
            i += 1
    return "".join(ret)


def quote_plus(url):
    if ' ' in url:
        # dirty hack
        convert_table[0x20] = '+'
        ret = quote(url)
        convert_table[0x20] = '%20'
        return ret
    return quote(url)


def unquote_plus(url):
    url = url.replace("+", " ")
    return unquote(url)


def auto_content_type(name):
    dot_offset = name.rfind(".")
    if dot_offset < 0:
        return common_types["default"]
    else:
        return common_types.get(name[dot_offset + 1:], common_types["default"])


def generate_url(d):
    ret = []
    if "schema" in d:
        ret.append(d["schema"] + "://")
    if "user" in d:
        ret.append(d["user"])
        if "password" in d:
            result.append(":" + d["password"])
        ret.append("@")
    if "host" in d:
        ret.append(d["host"])
    if "port" in d: 
        ret.append(":" + str(d["port"])) 
    if "path" in d:
        if not d["path"].startswith("/"):
            ret.append("/")
        ret.append(d["path"])
    if "query" in d:
        ret.append("?" + d["query"])
    if "params" in d:
        if isinstance(d["params"], list):
            ret.append(";" + ";".join(d["params"]))
        else:
            ret.append(";")
            ret.append(d["params"])
    if "fragment" in d:
        ret.append("#")
        ret.append(d["fragment"])
    return "".join(ret)


def urlparse(url):
    d = {}
    order = (("fragment", url.rfind("#")),
             ("params", url.rfind(";")),
             ("query", url.rfind("?")))
    order = sorted(order, key=lambda x: x[1], reverse=True)
    pv = len(url)
    for n, i in order:
        if i > 0:
            if n == "query" and url[i - 1] == "?":
                continue
            d[n] = url[i + 1:pv]
            pv = i
        else:
            break
    ne = url[:pv]
    hps = ne.split("://")
    host = hps[0]
    if len(hps) > 1:
        d["schema"] = hps[0]
        host = hps[1]
        # http://v2ex.com/static/img/qbar_light@2x.png' 
    us = host.find("@")
    p = host.find("/")
    if 0 < us < p:
        user = host[:us]
        host = host[us + 1:]
        ac = user.split(":")
        if len(ac) > 0:
            user = ac[0]
            d["password"] = ac[1]
        d["user"] = user
    p = host.find("/")
    if p > 0:
        d["path"] = host[p + 1:]
        host = host[:p]
    ph = host.split(":")
    port = None
    if len(ph) > 1:
        host = ph[0]
        d["port"] = ph[1]
    d["host"] = host
    if "path" not in d:
        d["path"] = "/"
    return d


def generate_cookie(cookie):
    ret = []
    has_unicode = False
    for k, v in cookie.items():
        if isinstance(k, unicode) or isinstance(v, unicode):
            has_unicode = True
        ret.append("%s=%s; " % (k, v))
    if has_unicode:
        return "".join(ret)[:-2].encode("utf-8")
    else:
        return "".join(ret)[:-2]


def parse_cookie(cookie):
    cd = {}
    for cookie in cookie.split(";"):
        kv = cookie.split("=")
        cd[kv[0].strip()] = kv[1].strip()
    return cd


def generate_setcookie(cl):
    ret = []
    for cd in cl:
        items_list = []
        for k, v in cd.items():
            if k == "cookie":
                item_list.append('%s; ' % v)
            else:
                item_list.append('%s=%s; ' % (k, v))
        ret.append("".join(items_list)[:-2])
        ret.append("\r\n")
    return "".join(ret)[:-2]


def parse_setcookie(data):
    cl = {}
    for line in data.split("\r\n"):
        lines = line.split(";")
        cookie = {}
        vl = lines[0]
        idx = vl.find("=")
        name = vl[:idx]
        value = vl[idx + 1:]
        cookie["value"] = value
        for part in lines[1:]:
            kv = part.split("=")
            # path=/ or httponly
            key = kv[0].strip()
            if len(kv) == 2:
                cookie[key] = kv[1]
            else:
                cookie[key] = True
        cl[name] = cookie
    return cl


def get_cookie(cookies):
    c = {}
    for key, value in cookies.items():
        c[key] = value["value"]
    return c


def parse_simple_post(data):
    post_dict = {}
    for i in data.split("&"):
        k, v = i.replace("+", " ").split("=")
        post_dict[unquote_plus(k)] = unquote_plus(v)
    return post_dict


def generate_request_header(header, method, path):
    sl = "%s %s %s\r\n" % (method, path, HTTP_VERSION)
    b = [sl]
    for k, v in header.items():
        b.append("%s: %s\r\n" % (k, v))
    return "".join(b)


def generate_response_header(header, status):
    sl = "%s %s\r\n" % (HTTP_VERSION, resp_codes["status"])
    b = [sl]
    for k, v in header.items():
        b.append("%s: %s\r\n" % (k, v))
    return "".join(b)


def parse_request_header(text):
    parts = text.split("\r\n")
    status_parts = parts[0].split(" ")
    status = {
        "method": status_parts[0],
        "path": status_parts[1],
        "protocol": status_parts[-1]
    }
    header = {}
    last = None
    for line in parts[1:]:
        kv = [x.strip() for x in line.split(":")]
        # maybe : in value
        if len(kv) > 2:
            kv[1] = ":".join(kv[1:])
            # maybe multiple lines
        if len(kv) == 1:
            header[last[0]] += "\r\n" + "".join(kv)
            continue
        last = kv
        header[kv[0]] = kv[1]
    cookie = header.get("Cookie", {})
    if cookie:
        del header["Cookie"]
        cookie = parse_cookie(cookie)
    return status, cookie, header


def parse_response_header(text):
    parts = text.split("\r\n")
    status_parts = parts[0].split(" ")
    status = {
        "protocol": status_parts[0],
        "status": int(status_parts[1]),
        "message": " ".join(status_parts[2:])
    }
    header = {}
    last = None
    for line in parts[1:]:
        kv = [x.strip() for x in line.split(":")]
        # maybe : in value
        if len(kv) > 2:
            kv[1] = ":".join(kv[1:])
            # maybe multiple lines
        if len(kv) == 1:
            header[last[0]] += "\r\n" + kv[0]
            continue
        last = kv
        key = kv[0]
        if key in header and "set-cookie" in key.lower():
            header[key] += "\r\n" + kv[1]
        else:
            header[kv[0]] = kv[1]
    cookie = {}
    cookie1 = header.get("Set-Cookie")
    if cookie1:
        cookie.update(parse_setcookie(cookie1))
    cookie2 = header.get("Set-Cookie2")
    if cookie2:
        cookie.update(parse_setcookie(cookie2))
    return status, cookie, header
