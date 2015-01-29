#! /usr/bin/env python
#-*-encoding=utf-8-*- 

import socket 
import os
import sys
import pdb
import errno 
import struct
import pwd 
import json 
import signal
import marshal

from select import *
from struct import unpack
from struct import pack
from cStringIO import StringIO 
from time import sleep 
from time import time


#server ip, port 
SERVER_IP = "0.0.0.0"
SERVER_PORT = 9905

MAX_LISTEN = 1024 


cons = {} 
g = globals() 
EAGAIN = errno.EAGAIN 


STATUS_HANDSHAKE = 0x1 << 1 
STATUS_REQUEST = 0x1 << 2
STATUS_WAIT_REMOTE = 0x1 << 3
STATUS_DATA = 0x1 << 4 


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
    log_file = open("/tmp/encrypted_server.log", "w+", buffering=0)
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
    g["SOCKS_REQUEST_OK"] = ("\x05\x00\x00\x01%s%s" % (socket.inet_aton("0.0.0.0"), pack(">H", 8888))).translate(SD)


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
        if data_count - data_sent > 102400: 
            remove_pollin(to_ctx) 
    else:
        #发完了,  关注pollin,  避免starve
        add_pollin(to_ctx)
        #不再关注pollout
        remove_pollout(ctx) 


def which_status(ctx): 
    from_conn = ctx["from_conn"] 
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
    if ctx["crypted"]:
        raw = text.translate(DS) 
    if raw.startswith("\x05\x01\x00"):
        return STATUS_REQUEST, raw 
    if not to_conn:
        clean_queue(ctx)
        return
    return STATUS_DATA, text 
    

def handle_request(ctx, text): 
    from_conn = ctx["from_conn"]
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
    #change status to DATA if this packet is not a REQUEST 
    try:        
        request_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        request_sock.setblocking(0)  
        request_fd = request_sock.fileno()
        flag = EPOLLIN|EPOLLOUT|EPOLLERR
        ep.register(request_fd, flag)
        ctx["pf"] = flag
    except Exception as e: 
        clean_queue(ctx)
        return 
    #request ctx 
    remote = (addr, port[0]) 
    print "connect", remote
    cons[request_fd] = {
            "in_buffer": StringIO(),
            "out_buffer": StringIO(),
            "from_conn": request_sock,
            "to_conn": from_conn,
            "to_fd": from_conn.fileno(),
            "crypted": False, 
            "request": remote, 
            "pf": flag,
            "status": STATUS_WAIT_REMOTE, 
            } 
    ctx["to_conn"] = request_sock 
    ctx["to_fd"] = request_fd
    ctx["request"] = remote
    ctx["status"] = STATUS_WAIT_REMOTE
    try: 
        request_sock.connect(remote)
    except socket.error as e: 
        if e.errno != errno.EINPROGRESS: 
            clean_queue(ctx) 
        

def handle_remote_connected(ctx): 
    to_conn = ctx["to_conn"]
    to_ctx = cons[to_conn.fileno()] 
    to_ctx["out_buffer"].write(SOCKS_REQUEST_OK) 
    #不再需要pollout
    remove_pollout(ctx)
    #放到write later处理
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
    in_buffer = ctx["in_buffer"]
    to_ctx = cons[to_conn.fileno()]
    to_out_buffer = to_ctx["out_buffer"] 
    in_buffer.write(text) 
    try:
        read_to_buffer(from_conn, in_buffer)
    except socket.error as e:
        clean_queue(ctx)
        return
    data_count = in_buffer.tell() 
    if not ctx["crypted"]:
        raw = in_buffer.getvalue().translate(SD)
    else:
        raw = in_buffer.getvalue().translate(DS)
    in_buffer.truncate(0) 
    to_out_buffer.write(raw)
    handle_write_later(to_ctx) 


def handle_pollin(ctx):
    status = ctx["status"] 
    result = which_status(ctx) 
    if not result:
        return 
    status, text = result 
    if status & STATUS_REQUEST: 
        handle_request(ctx, text) 
        return

    if status & STATUS_DATA: 
        handle_redirect_data(ctx, text)


def handle_connection(): 
    conn, addr = sock.accept() 
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
            "status": STATUS_REQUEST
            } 



def handle_socket(event): 
    if event & EPOLLIN:
        handle_connection() 
    if event & EPOLLERR:
        raise Exception("fatal error") 


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


def add_pollin(ctx):
    #可以检测一下用不用修改
    if "pf" not in ctx:
        return
    after =  ctx["pf"] | EPOLLIN
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
        #控制pollout的busyloop
        if event & EPOLLOUT: 
            g["pollout"] += 1
            if ctx["status"] & STATUS_WAIT_REMOTE:
                handle_remote_connected(ctx) 
            elif ctx["out_buffer"].tell():
                handle_write_later(ctx) 
        if event & EPOLLIN: 
            g["pollin"] += 1
            handle_pollin(ctx) 


"""
def debug(*args):
    pdb.set_trace() 
"""

def poll_wait(): 
    #signal.signal(signal.SIGINT, debug)
    g["pollout"] = 0
    g["pollin" ]  = 0
    while True: 
        try: 
            handle_event() 
        except IOError as e:
            print e

if __name__ == "__main__":
    set_globals() 
    #run_as_user("quark") 
    #daemonize()
    poll_wait()
