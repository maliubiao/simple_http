#-*-encoding=utf-8-*- 
from _http import *

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


def get(url, **kwargs):
    return request(url, method=METHOD_GET, **kwargs)

def head(url, **kwargs):
    return request(url, method=METHOD_HEAD, header_only=True, **kwargs)

def delete(url, **kwargs):
    return request(url, method=METHOD_DELETE, **kwargs) 

def trace(url, **kwargs):
    return request(url, method=METHOD_TRACE, **kwargs)

def options(url, **kwargs):
    return request(url, method=METHOD_OPTIONS, **kwargs)

def put(url, **kwargs):
    return request(url, method=METHOD_PUT, **kwargs)

def post(url, **kwargs):
    return request(url, method=METHOD_POST, **kwargs) 


def request(url, **kwargs): 
    redirect = kwargs.get("redirect", 1)
    assert redirect > 0
    new_url = url 
    urlset = set()
    while redirect:
        redirect = redirect - 1 
        if new_url in urlset:
            raise socket.error("endless redirect")
        header, body = do_request(new_url, **kwargs)
        urlset.add(url)
        status = header["status"]
        if status == 301 or status == 302:
            new_url = header.get("Location", header.get("location")) 
        else:
            break
        print "redirect to", new_url
    return header, body 


def do_request(url, **kwargs): 
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
    if proxy.startswith("http"):
        urld["scheme"] = "http"
    else: 
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
    if not port in (80, 443):
        header["Host"] = "%s:%d" % (host, port) 
    else:
        header["Host"] = host 
    if kwargs.get("method") in (METHOD_PUT, METHOD_POST): 
        content = generate_post(header, kwargs["payload"]) 
        header["Content-Length"] = str(len(content)) 
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
    if kwargs.get("method") in (METHOD_PUT, METHOD_POST):
        request_list.append(content)
    #args for send_http
    body = "".join(request_list)       
    remote = kwargs.get("remote", (host, port)) 
    return send_http(remote, use_ssl, body, 
            kwargs.get("timeout", default_timeout),
            proxy, kwargs.get("header_only", False))

            

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
    hbuf.write(data)
    hdr = hbuf.getvalue()
    skip = 0 
    hend = hdr.find(HEADER_END) 
    if hend < 0: 
        hend = hdr.find(HEADER_END2)
        if hend < 0:
            #slow network, wait for header 
            return None, None 
        else:
            skip = 2
    else:
        skip = 4 
    header = parse_server_header(hdr[:hend]) 
    return header, hdr[hend+skip:] 



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
        data = remote.recv(40960) 
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
            if chunked_end < 0 or data[chunked_end-1].isdigit(): 
                continue
            cbuf.getvalue() 
            normal = cStringIO.StringIO()
            handle_chunked(cbuf, normal) 
            cbuf.close() 
            return header, normal.getvalue() 
        #Content-Length
        if cbuf.tell() >= total_length: 
            break 
    if not header:
        raise socket.error("remote error: %s:%d" % remote.getpeername())
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
        sock.connect((proxyd["host"], int(proxyd["port"])))
    elif scheme == "socks5": 
        proxy_type = "socks5"
        connect_sock5(sock, remote, (proxyd["host"], int(proxyd["port"]))) 
    else:
        raise socket.error("unknown proxy type")
    return proxy_type 


#connection pool
sconf =  {} 
session = {}


def connect(remote): 
    sock = socket.socket(socket.AF_INET, 
            socket.SOCK_STREAM)
    sock.connect(remote) 
    return sock


def get_sock(remote): 
    host = "%s:%d" % remote 
    #检测一下socket是否已经关闭 
    sock = session[host].pop() 
    #send_http会恢复这个标志
    sock.setblocking(0) 
    try: 
        x = sock.recv(1) 
        sock = connect(remote)
    except socket.error as e:
        if e.errno != errno.EAGAIN: 
            sock = connect(remote) 
    return sock



def session_pool(remote): 
    #如果配置了连接池 
    host = "%s:%d" % remote 
    if host in sconf: 
        #如果池里有项
        if host in session:
            #如果有可用的
            if len(session[host]):
                sock = get_sock(remote)
            #没有则新建
            else:
                sock = connect(remote)
        #如果池里没有则新建
        else: 
            sock = connect(remote)
            session[host] = []
    #没有配置连接池只用一次
    else:
        sock = connect(remote)
    return sock



def send_http(remote, use_ssl, message, timeout, proxy=None, header_only=False): 
    #if there is a proxy , connect proxy server instead 
    proxy_type = None 
    if proxy: 
        #用代理则先连接代理服务器
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        proxy_type = connect_proxy(sock, remote, proxy)
    else: 
        sock = session_pool(remote)
    sock.settimeout(timeout) 
    #用代理不能封闭ssl
    if use_ssl and proxy_type != "http":
        sock = ssl.wrap_socket(sock) 
    #略粗暴，可能发不全
    sock.send(message) 
    header, body = wait_response(sock, header_only) 
    #如果需要缓存连接则添加到队列， 否则直接关闭连接
    host = "%s:%d" % remote
    if (not proxy and
            sock and
            header and
            host in sconf and
            host in session and 
            len(session[host]) < sconf[host]):
        #出错的不会被再添加 
        session[host].append(sock) 
    else:
        sock.close() 
    #handle compressed stream: gzip, deflate 
    if not header_only and header: 
        #maybe gzip stream
        if header.get("Content-Encoding") == "gzip": 
            body = zlib.decompress(body, 16+zlib.MAX_WBITS)  
        elif header.get("Content-Encoding") == "deflate":
            body = zlib.decompress(body, -zlib.MAX_WBITS)  
    return header, body 
