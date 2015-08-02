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
    urlset = {new_url: 1} 
    while redirect:
        redirect = redirect - 1 
        if urlset[new_url] > 2: 
            raise socket.error("endless redirect")
        res = do_request(new_url, **kwargs)
        res["url"] = new_url
        cookie = res.get("cookie")
        if "cookie" not in kwargs:
            kwargs["cookie"] = {}
        if cookie:
            kwargs["cookie"].update(get_cookie(cookie))
        header = res["header"] 
        status = res["status"]
        if status == 301 or status == 302:
            new_url = header.get("Location", header.get("location")) 
        else:
            break 
        print "redirect to", new_url 
        if new_url in urlset:
            urlset[new_url] += 1
        else:
            urlset[new_url] = 1 
    return res



def do_request(url, **kwargs): 
    request = generate_request(url, **kwargs)
    return send_http(request) 


            
def generate_request(url, **kwargs): 
    rl = [] 
    url_parts = urlparse(url) 
    #http basic authorization 
    basicauth = basic_auth_msg(url_parts.get("user"), url_parts.get("password")) 
    if "user" in url_parts:
        del url_parts["user"]
    if "password" in url_parts:        
        del url_parts["password"] 
    proxy = kwargs.get("proxy", "")
    if proxy:
        pauth = proxy_auth_msg(proxy)
    else:
        pauth = None 
    #maybe ssl 
    port = int(url_parts.get("port", 80)) 
    use_ssl = False
    if url_parts.get("schema") == "https": 
        use_ssl = True
        port = 443
        if not has_ssl:
            raise socket.error("Unsupported schema") 
    #handle query string
    if kwargs.get("query"):
        url_parts["query"] = generate_query(kwargs["query"]) 
    host = url_parts["host"] 
    #http proxy: remove schema://host:port 
    if proxy.startswith("http"):
        url_parts["schema"] = "http"
    else: 
        del url_parts["host"] 
        if "schema" in url_parts:
            del url_parts["schema"] 
        if "port" in url_parts: 
            del url_parts["port"] 
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
    path = generate_url(url_parts) 
    method= kwargs.get("method", METHOD_GET) 
    #for basic authorization 
    if basicauth: header["Authorization"] = basicauth 
    #for basic proxy authorization
    if pauth: header["Proxy-Authorization"] = pauth
    rl.append(generate_request_header(header, method, path)) 
    #generate cookie and HEADER_END
    if kwargs.get("cookie"):
        rl.append("Cookie: ")    
        rl.append(generate_cookie(kwargs["cookie"])) 
        rl.append(HEADER_END) 
    else:
        rl.append("\r\n") 
    if kwargs.get("method") in (METHOD_PUT, METHOD_POST):
        rl.append(content)
    #args for send_http
    body = "".join(rl)       
    remote = kwargs.get("remote", (host, port)) 
    return {
            "body": body,
            "remote": remote,
            "ssl": use_ssl,
            "timeout": kwargs.get("timeout", default_timeout),
            "proxy": proxy,
            "header_only": kwargs.get("header_only", False),
            }


def decode_chunk_stream(response): 
    goout = False
    b = response["chunked_b"]
    recv = response["recv"]
    done = False 
    recv_end = recv.tell() 
    recv.seek(response["chunked_idx"], io.SEEK_SET) 
    while True: 
        back_idx = recv.tell()
        num = "" 
        while True: 
            char = recv.read(1) 
            if not char:
                goout = True
                break 
            if char == "\r": 
                break
            num += char 
        if goout:
            recv.seek(back_idx, io.SEEK_SET) 
            break
        recv.seek(1, io.SEEK_CUR)
        x = int(num, 16) 
        if not x:
            done = True
            break
        chunk = recv.read(x) 
        if len(chunk) != x:
            recv.seek(back_idx, io.SEEK_SET)
            break
        recv.seek(2, io.SEEK_CUR)
        b.write(chunk) 
    response["chunked_idx"] = recv.tell()
    recv.seek(recv_end, io.SEEK_SET) 
    if done:
        response["recv"] = response["chunked_b"]
        del response["chunked_b"] 
        del response["chunked_idx"] 
    return done



def parse_header(response):
    recv = response["recv"]
    data = recv.getvalue()
    idx = data.find(HEADER_END)
    if not idx:
        data.find(HEADER_END2)
        skip = 2
    else:
        skip = 4
    if idx < 0:
        return 
    recv.truncate(0)
    recv.write(data[idx+skip:])
    status, cookie, header = parse_response_header(data[:idx]) 
    response.update(status)
    response["cookie"] = cookie
    response["header"] = header
    if "Content-Length" in header:
        response["total_length"] = int(header["Content-Length"]) 
    if header.get("Transfer-Encoding") == "chunked":
        response["chunked"] = True
        response["chunked_b"] = cStringIO.StringIO()
        response["chunked_idx"] = 0 
    return header


def wait_response(request): 
    has_header = False 
    recv = cStringIO.StringIO() 
    remote = request["sock"]
    header = None 
    response = {"recv": recv} 
    while True: 
        data = remote.recv(40960) 
        #remote closed
        if not data: 
            break 
        recv.write(data) 
        if not has_header: 
            header = parse_header(response)
            if not header:
                continue 
            if request["header_only"]: 
                break 
            has_header = True
        if response.get("chunked") and decode_chunk_stream(response): 
            break 
        if recv.tell() >= response.get("total_length", 0xffffffff): 
            break 
    if not header:
        raise socket.error("remote error: %s:%d" % remote.getpeername()) 
    return response



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
        raise socket.error("unexpected response packet") 



def connect_proxy(sock, remote, proxy): 
    proxy_type = None
    url_parts = urlparse(proxy)
    schema = url_parts["schema"]
    if schema in "https": 
        proxy_type = "http"
        sock.connect((url_parts["host"], int(url_parts["port"])))
    elif schema == "socks5": 
        proxy_type = "socks5"
        connect_sock5(sock, remote,
            (url_parts["host"], int(url_parts["port"]))) 
    else:
        raise socket.error("unknown proxy type")
    return proxy_type 



def send_tcp(sock, message): 
    remain = message
    while True:
        idx = sock.send(remain) 
        if idx == len(remain):
            break
        remain = remain[idx:]



def send_http(request): 
    #if there is a proxy , connect proxy server instead 
    proxy_type = None 
    remote = request["remote"] 
    sock = socket.socket(socket.AF_INET, 
            socket.SOCK_STREAM) 
    if request["proxy"]: 
        #用代理则先连接代理服务器 
        proxy_type = connect_proxy(sock, remote, request["proxy"])
    else: 
        sock.connect(remote) 
    sock.settimeout(request["timeout"]) 
    #用代理不能封闭ssl
    if request["ssl"] and proxy_type != "http":
        sock = ssl.wrap_socket(sock) 
    request["sock"] = sock
    #略粗暴，可能发不全
    send_tcp(sock, request["body"]) 
    response = wait_response(request)
    #如果需要缓存连接则添加到队列， 否则直接关闭连接
    host = "%s:%d" % remote 
    header = response["header"] 
    text = response["recv"].getvalue() 
    del response["recv"] 
    if not request.get("header_only") and header: 
        #maybe gzip stream
        if header.get("Content-Encoding") == "gzip": 
            text = zlib.decompress(text, 16+zlib.MAX_WBITS)  
        elif header.get("Content-Encoding") == "deflate":
            text = zlib.decompress(text, -zlib.MAX_WBITS)  
    response["text"] = text
    return response
