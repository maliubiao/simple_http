#! /usr/bin/env python
#-*-encoding=utf-8-*-

import socket 
import os
import sys
import pdb
import errno 
import struct
import pwd 
import marshal 


from struct import unpack
from struct import pack
from cStringIO import StringIO 
from time import sleep 
from time import time
from select import *
from fcntl import *


#server ip, port 
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9988

MAX_LISTEN = 1024
REMOTE = ("127.0.0.1", 9905)


cons = {} 
g = globals() 

#clients allowed
allowed  = {
        "127.0.0.1": None 
        }

forbidden  = {
        }


EAGAIN = errno.EAGAIN


STATUS_HANDSHAKE = 0x1 << 1 
STATUS_REQUEST = 0x1 << 2
STATUS_WAIT_REMOTE = 0x1 << 3
STATUS_DATA = 0x1 << 4

STATUS_SERVER_HANDSHKAE = 0x1 << 5
STATUS_SERVER_REQUEST = 0x1 << 6 
STATUS_SERVER_CONNECTED = 0x1 <<7
STATUS_SERVER_WAIT_REMOTE = 0x1 << 8 


def run_as_user(user):
    try:
        db = pwd.getpwnam(user)
    except KeyError:
        raise OSError("user doesn't exists") 
    try:
        os.setgid(db.pw_gid)
    except OSError:        
        raise OSError("change gid failed") 
    try:
        os.setuid(db.pw_uid)
    except OSError:
        raise OSError("change uid failed") 



def daemonize():
    log_file = open("/tmp/encrypted_client.log", "w+", buffering=0)
    try:
        status = os.fork()
    except OSError as e:
        print e
    if not status: 
        os.setsid() 
        sys.stdin = open("/dev/null", "r")
        sys.stdout = log_file
        sys.stderr = log_file
        try:
            status2 = os.fork()
        except OSError as e:
            print e
        if status2:
            exit()
    else:
        exit()        


def read_key(keyfile): 
    f = open(keyfile, "r")
    result = marshal.loads(f.read())
    f.close()
    return result


def set_globals(): 
    g["sock"] = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, SERVER_PORT)) 
    sock.listen(MAX_LISTEN) 
    g["sockfd"] = sock.fileno() 
    g["ep"] = epoll()
    ep.register(sockfd, EPOLLIN | EPOLLERR)
    g["SD"], g["DS"] = read_key("key") 
    g["SOCKS_HANDSHAKE_CLIENT"] = "\x05\x01\x00".translate(SD)
    g["SOCKS_HANDSHAKE_SERVER"] = "\x05\x00".translate(SD)
    g["SOCKS_REQUEST_OK_RAW"] = "\x05\x00\x00\x01%s%s" % (socket.inet_aton("0.0.0.0"), pack(">H", 8888))
    g["SOCKS_REQUEST_OK"] = SOCKS_REQUEST_OK_RAW.translate(SD) 


def clean_profile(ctx): 
    #close client buffer
    ctx["in_buffer"].close()
    ctx["out_buffer"].close() 
    #close client socket
    try: 
        ctx["from_conn"].shutdown(socket.SHUT_RDWR) 
    except Exception as e:
        pass
    try:
        ctx["from_conn"].close() 
    except Exception as e:
        pass
    try:
        ctx["to_conn"].shutdown(socket.SHUT_RDWR)
    except Exception as e:
        pass
    try:
        ctx["to_conn"].close()
    except Exception as e:
        pass
    try:
        ep.unregister(ctx["from_conn"].fileno()) 
    except Exception as e:
        pass

def clean_queue(ctx): 
    #close pipe 
    server = True
    try:
        server_fd  = ctx["to_conn"].fileno()
    except:
        server = False 
    clean_profile(ctx) 
    del cons[ctx["fd"]] 
    if server:
        ctx_server = cons[server_fd]
        clean_profile(ctx_server) 
        del cons[server_fd]

    
def handle_write_later(ctx): 
    out_buffer = ctx["out_buffer"]
    from_conn = ctx["from_conn"] 
    to_ctx = cons[from_conn.fileno()]
    data = out_buffer.getvalue()
    data_count = len(data) 
    try: 
        data_sent = from_conn.send(data) 
    except socket.error as e: 
        if e.errno != EAGAIN: 
            clean_queue(ctx)
        return 
    out_buffer.truncate(0)
    if data_sent != data_count: 
        out_buffer.write(data[data_sent:]) 
        #下次再发, 关注pollout
        add_pollout(ctx) 
        #堆积了100k， 取消pollin, 避免busyloop
        if data_count - data_sent > 1024000: 
            remove_pollin(to_ctx) 
    else: 
        remove_pollout(ctx)
    if out_buffer.tell() < 1024000: 
        #发完了,  关注pollin,  避免starve
        add_pollin(to_ctx)


def handle_handshake(ctx): 
    from_conn = ctx["from_conn"]
    fd = ctx["fd"] 
    try:
        raw = from_conn.recv(128) 
    except socket.error as e:
        clean_queue(ctx)
        return
    #maybe RST
    if not raw: 
        clean_queue(ctx)
        return 
    #connect, or bind
    if not (raw.startswith("\x05\x01") or raw.startswith("\x05\x02")): 
        clean_queue(ctx)
        return
    #handshake packet or not 
    if len(raw) > 12:
        clean_queue(ctx)
        return
    #connect our server
    try:        
        request_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        request_sock.setblocking(0)  
        request_fd = request_sock.fileno()
        flag =  EPOLLIN|EPOLLOUT|EPOLLERR
        ep.register(request_fd, flag)
        ctx["pf"] = flag
    except Exception as e: 
        clean_queue(ctx)
        return 
    #request ctx 
    cons[request_fd] = {
            "in_buffer": StringIO(),
            "out_buffer": StringIO(),
            "from_conn": request_sock,
            "to_conn": from_conn,
            "to_fd": from_conn.fileno(),
            "crypted": False, 
            "request": "",
            "pf": flag, 
            "status": STATUS_SERVER_CONNECTED, 
            } 
    ctx["to_conn"] = request_sock
    ctx["to_fd"] = request_fd 
    #next status , CONNECTED
    ctx["status"] = STATUS_REQUEST 
    try: 
        request_sock.connect(REMOTE)
    except socket.error as e: 
        #close connection if it's a real exception 
        if e.errno != errno.EINPROGRESS: 
            clean_queue(ctx) 

def notify_server_down(ctx): 
    status = "HTTP/1.1 500 Internal Server Error"
    content_type = "Content-Type: text/html"
    msg = """<html>
        <head>转发服务器已经关闭</head>
        <body><h1>转发服务器已经关闭，请联系作者, 或者刷新重试</h1></body> 
    </html>
    """
    content_length = "Content-Length: %d" % len(msg)
    response =  "\r\n".join((status, content_type, content_length, msg))
    try:
        count = ctx["from_conn"].send(response) 
    except socket.error:
        ctx["out_buffer"].write(response)

def which_status(ctx): 
    fd = ctx["fd"]
    from_conn = ctx["from_conn"] 
    status = None 
    to_conn = ctx["to_conn"] 
    try:
        text = from_conn.recv(256) 
    except socket.error as e: 
        clean_queue(ctx)
        return 
    #may RST
    if not text: 
        clean_queue(ctx)
        return 
    raw = text
    #if this msg if from server, decrypt it
    if not ctx["crypted"]: 
        raw = text.translate(DS)           
    if raw.startswith("\x05\x00\x00\x01"):
        status = STATUS_SERVER_WAIT_REMOTE
    elif raw.startswith("\x05\x01\x00"):
        status = STATUS_REQUEST 
    else:            
        status = STATUS_DATA 
    return status, text 


def handle_server_connected(ctx): 
    to_ctx = cons[ctx["to_conn"].fileno()] 
    to_ctx["out_buffer"].write("\x05\x00") 
    remove_pollout(ctx)
    handle_write_later(to_ctx)
    ctx["status"] = STATUS_REQUEST
    to_ctx["status"] = STATUS_REQUEST
    

def handle_new_request(ctx, text): 
    to_conn = ctx["to_conn"]
    to_ctx = cons[to_conn.fileno()] 
    parse_buffer = StringIO()
    parse_buffer.write(text)
    parse_buffer.seek(4) 
    addr_to = text[3]
    addr_type = ord(addr_to)
    if addr_type == 1:
        addr = socket.inet_ntoa(parse_buffer.read(4))
        addr_to += addr
    elif addr_type == 3: 
        addr_len = parse_buffer.read(1)
        addr = parse_buffer.read(ord(addr_len))
        addr_to += addr_len + addr
    elif addr_type == 4:
        addr = parse_buffer.read(16)
        net = socket.inet_ntop(socket.AF_INET6, addr)
        addr_to += net
    else:
        clean_queue(ctx)
        return
    addr_port = parse_buffer.read(2) 
    parse_buffer.close()
    addr_to += addr_port

    try:
        port = unpack(">H", addr_port)
    except struct.error: 
        clean_queue(ctx)
        return 
    remote = (addr, port[0]) 
    print "new request %s:%d" % remote
    ctx["request"] = remote 
    to_ctx["request"] = remote 
    try:        
        to_conn.send(text.translate(SD)) 
    except socket.error as e: 
        if e.errno == EAGAIN:
            to_ctx["out_buffer"].write(text.translate(SD))  


def handle_server_wait_remote(ctx): 
    to_conn = ctx["to_conn"]
    to_ctx = cons[to_conn.fileno()] 
    to_ctx["out_buffer"].write(SOCKS_REQUEST_OK_RAW)
    handle_write_later(to_ctx)
    ctx["status"] = STATUS_DATA
    to_ctx["status"] = STATUS_DATA 

def read_to_buffer(con, buf):
    while 1:
        try:
            mark = buf.tell()
            buf.write(con.recv(4096000))
            if buf.tell() == mark:
                break 
        except socket.error as e:
            if e.errno == EAGAIN:
                break
            raise e 



def handle_redirect_data(ctx, text): 
    from_conn = ctx["from_conn"]
    to_conn = ctx["to_conn"]
    to_ctx = cons[ctx["to_conn"].fileno()]
    to_out_buffer = to_ctx["out_buffer"] 
    in_buffer = ctx["in_buffer"] 
    in_buffer.write(text)  
    try:
        read_to_buffer(from_conn, in_buffer)
    except socket.error as e: 
        clean_queue(ctx)
        return
    data_count = in_buffer.tell() 
    raw = in_buffer.getvalue()
    if ctx["crypted"]:
        raw = raw.translate(SD)
    else:
        raw = raw.translate(DS)
    in_buffer.truncate(0) 
    to_out_buffer.write(raw)
    handle_write_later(to_ctx)


def handle_pollin(ctx): 
    status = ctx["status"] 
    if status & STATUS_HANDSHAKE: 
        handle_handshake(ctx)
        return 
    result = which_status(ctx)
    if not result:
        return
    status, text = result 

    if status & STATUS_REQUEST: 
        handle_new_request(ctx, text) 
        return

    if status & STATUS_SERVER_WAIT_REMOTE: 
        handle_server_wait_remote(ctx)
        return 

    if status & STATUS_DATA: 
        handle_redirect_data(ctx, text)

def close_conn(conn): 
    try:
        conn.shutdown(socket.SHUT_RDWR) 
        conn.close() 
    except Exception:
        pass


def handle_connection(): 
    conn, addr = sock.accept() 
    ip  = addr[0]
    if ip in forbidden:
        close_conn(conn)
        return 
    """
    if not ip in allowed:
        close_conn(conn)
        return 
    """
    fd = conn.fileno() 
    conn.setblocking(0)
    flag = EPOLLIN|EPOLLERR
    ep.register(fd, flag)
    #add fd to queue
    cons[fd] = {
            "in_buffer": StringIO(),
            "out_buffer": StringIO(),
            "from_conn": conn,
            "to_conn": None,
            "to_fd": -1,
            "crypted": True,
            "request": None,
            "pf": flag, 
            "status": STATUS_HANDSHAKE 
            } 

#fileno()可以优化掉

def handle_socket(event): 
    if event & EPOLLIN:
        handle_connection() 
    if event & EPOLLERR:
        raise Exception("fatal error") 


def add_pollin(ctx):
    #可以检测一下用不用修改
    if "pf" not in ctx:
        return
    after =  ctx["pf"] | EPOLLIN
    ctx["pf"] = after 
    if ctx["from_conn"]:
        ep.modify(ctx["from_conn"].fileno(),
                after) 


def remove_pollin(ctx):
    if "pf" not in ctx:
        return
    after = ctx["pf"] & ~EPOLLIN
    ctx["pf"] = after 
    if ctx["from_conn"]:
        ep.modify(ctx["from_conn"].fileno(), 
                after) 


def remove_pollout(ctx): 
    if "pf" not in ctx:
        return 
    after = ctx["pf"] & ~EPOLLOUT
    ctx["pf"] = after 
    if ctx["from_conn"]:
        ep.modify(ctx["from_conn"].fileno(),
                after) 


def add_pollout(ctx): 
    if "pf" not in ctx:
        return 
    after =  ctx["pf"] | EPOLLOUT
    ctx["pf"] = after 
    if ctx["from_conn"]:
        ep.modify(ctx["from_conn"].fileno(),
                after) 


def handle_event(): 
    for fd, event in ep.poll(1): 
        if fd == sockfd: 
            handle_socket(event) 
            continue
        if fd not in cons: 
            continue 
        ctx = cons[fd] 
        ctx["fd"] = fd 
        if event & EPOLLERR:
            clean_queue(ctx)
            continue 
        if event & EPOLLOUT:
            if ctx["status"] & STATUS_SERVER_CONNECTED: 
                handle_server_connected(ctx)
            elif ctx["out_buffer"].tell():
                handle_write_later(ctx)
            #出现这个是bug
            else:   
                pdb.set_trace() 
        if event & EPOLLIN: 
            handle_pollin(ctx) 



def poll_wait(): 
    while True: 
        try:
            handle_event() 
        except IOError:
            pass

if __name__ == "__main__":
    set_globals() 
    #daemonize()
    poll_wait()
