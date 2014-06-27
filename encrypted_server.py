#! /usr/bin/env python
#-*-encoding=utf-8-*- 

import socket 
import os
import pdb
import errno 
import struct
import pwd 
import json 
#alias 
from select import *
from fcntl import *
from struct import unpack
from struct import pack
from cStringIO import StringIO 
from time import sleep 
from time import time
import marshal


#server ip, port 
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9905

MAX_LISTEN = 128

_AF_INET = socket.AF_INET
_SOCK_STREAM = socket.SOCK_STREAM
_SOL_SOCKET = socket.SOL_SOCKET
_SO_REUSEADDR = socket.SO_REUSEADDR
_SO_ERROR = socket.SO_ERROR
_O_NONBLOCK = os.O_NONBLOCK
_socket = socket.socket
_fromfd = socket.fromfd
_inet_ntop = socket.inet_ntop
_inet_aton = socket.inet_aton 


sock = None
sockfd = None
epoll_object = None
cons = {} 


def read_key(keyfile): 
    f = open(keyfile, "r")
    result = marshal.loads(f.read())
    f.close()
    return result

SD, DS = read_key("key")

SOCKS_HANDSHAKE_CLIENT = "\x05\x01\x00".translate(SD)
SOCKS_HANDSHAKE_SERVER = "\x05\x00".translate(SD)
SOCKS_REQUEST_OK = ("\x05\x00\x00\x01%s%s" % (_inet_aton("0.0.0.0"), pack(">H", 8888))).translate(SD)

STATUS_HANDSHAKE = 0x1 << 1 
STATUS_REQUEST = 0x1 << 2
STATUS_WAIT_REMOTE = 0x1 << 3
STATUS_DATA = 0x1 << 4

log_file = open("server.log", "w+")

def run_as_user(user):
    try:
        db = pwd.getpwnam(user)
    except KeyError:
        raise Exception("user doesn't exists") 
    try:
        os.setgid(db.pw_gid)
    except OSError:        
        raise Exception("change gid failed") 
    try:
        os.setuid(db.pw_uid)
    except OSError:
        raise Exception("change uid failed") 

def daemonize():
    try:
        status = os.fork()
    except OSError as e:
        print e
    if not status: 
        os.setsid()
        os.close(0)
        os.close(1)
        os.close(2)
        stdin = open("/dev/null", "r")
        os.dup2(log_file.fileno(), 1)
        os.dup2(log_file.fileno(), 2)
        try:
            status2 = os.fork()
        except OSError as e:
            print e
        if status2:
            exit()
    else:
        exit()        


def server_config():
    global sock, sockfd, epoll_object
    sock = _socket(_AF_INET, _SOCK_STREAM) 
    sock.setsockopt(_SOL_SOCKET, _SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, SERVER_PORT)) 
    sock.listen(MAX_LISTEN) 
    sock.setsockopt(_SOL_SOCKET, _SO_REUSEADDR, 1) 
    sockfd = sock.fileno() 
    epoll_object = epoll()
    epoll_object.register(sockfd, EPOLLIN | EPOLLERR | EPOLLHUP) 

def clean_profile(context): 
    #close client buffer
    context["in_buffer"].close()
    context["out_buffer"].close() 
    #close client socket
    try: 
        context["from_conn"].shutdown(socket.SHUT_RDWR) 
    except Exception as e:
        pass
    try:
        context["from_conn"].close() 
    except Exception as e: 
        pass
    try:
        context["to_conn"].shutdown(socket.SHUT_RDWR)
    except Exception as e: 
        pass
    try:
        context["to_conn"].close()
    except Exception as e: 
        pass
    try: 
        epoll_object.unregister(context["from_conn"].fileno()) 
    except Exception as e: 
        pass

def clean_queue(fd): 
    if fd not in cons:
        return 
    context_client = cons[fd] 
    server = True
    try:
        server_fd  = context_client["to_conn"].fileno()
    except:
        server = False
    clean_profile(context_client) 
    del cons[fd] 
    if server:
        context_server = cons[server_fd]
        clean_profile(context_server) 
        del cons[server_fd]


def handle_write_later(context): 
    out_buffer = context["out_buffer"]
    from_conn = context["from_conn"]
    if out_buffer.tell(): 
        try: 
            data = out_buffer.getvalue()
            data_count = len(data) 
            data_sent = from_conn.send(data) 
            if data_sent != data_count: 
                out_buffer.truncate(0)
                out_buffer.write(data[data_sent:])
                return
        except socket.error as e: 
            if e.errno != errno.EAGAIN: 
                clean_queue(context["fd"])
            return
        out_buffer.truncate(0) 


def handle_handshake(context): 
    from_conn = context["from_conn"]
    out_buffer = context["out_buffer"]
    raw = from_conn.recv(128) 
    #maybe RST
    if not raw: 
        clean_queue(context["fd"])
        return 
    if raw != SOCKS_HANDSHAKE_CLIENT: 
        print "weird handshake"
        clean_queue(context["fd"])
        return 
    try: 
        from_conn.send(SOCKS_HANDSHAKE_SERVER)
    except socket.error:
        out_buffer.write(SOCKS_HANDSHAKE_SERVER) 
        return
    context["status"] = STATUS_REQUEST 
    return 

def which_status(context): 
    from_conn = context["from_conn"]
    fd = context["fd"]
    try:
        text = from_conn.recv(256) 
    except socket.error:
        print "broken pipe error"
        clean_queue(fd)
        return 
    #may RST 
    if not text: 
        print context["request"]
        clean_queue(fd)
        return 
    raw = text.translate(DS) 
    if not raw.startswith("\x05\x01\x00"):
        context["status"] = STATUS_DATA 
    else:            
        context["status"] = STATUS_REQUEST 
        text = raw
    return context["status"], text

def handle_request(context, text): 
    from_conn = context["from_conn"]
    parse_buffer = StringIO()
    parse_buffer.write(text)
    parse_buffer.seek(4) 
    addr_to = text[3]
    addr_type = ord(addr_to)
    if addr_type == 1:
        addr = parse_buffer.read(4)
        addr_to += addr
    elif addr_type == 3: 
        addr_len = parse_buffer.read(1)
        addr = parse_buffer.read(ord(addr_len))
        addr_to += addr_len + addr
    elif addr_type == 4:
        addr = parse_buffer.read(16)
        net = _inet_ntop(socket.AF_INET6, addr)
        addr_to += net
    else: 
        clean_queue(context["fd"])
        return
    addr_port = parse_buffer.read(2) 
    parse_buffer.close()
    addr_to += addr_port 
    to_data =False
    try:
        port = unpack(">H", addr_port)
    except struct.error: 
        to_data = True 
    #change status to DATA if this packet is not a REQUEST
    if not to_data: 
        try:        
            request_sock = _socket(_AF_INET, _SOCK_STREAM)
            request_sock.setblocking(0)  
            request_fd = request_sock.fileno()
            epoll_object.register(request_fd, EPOLLIN|EPOLLOUT) 
        except Exception as e: 
            clean_queue(context["fd"])
            return 
        #request context 
        remote = (addr, port[0]) 
        print "connect", remote
        cons[request_fd] = {
                "in_buffer": StringIO(),
                "out_buffer": StringIO(),
                "from_conn": request_sock,
                "to_conn": from_conn,
                "crypted": False, 
                "request": remote,
                "status": STATUS_WAIT_REMOTE,
                "active": time()
                } 
        if context["to_conn"]: 
            context["to_conn"].close()                   
            context["to_conn"].shutdown(socket.SHUT_RDWR)
            context["out_buffer"].close()
            context["in_buffer"].close()
        context["to_conn"] = request_sock
        context["status"] = 0
        context["request"] = remote
        try: 
            request_sock.connect(remote)
        except socket.error as e: 
            #close connection if it's a real exception 
            if e.errno != errno.EINPROGRESS: 
                clean_queue(context["fd"]) 
        return
    else: 
        context["status"] = STATUS_DATA 

def handle_remote_connected(context): 
    to_conn = context["to_conn"]
    to_context = cons[to_conn.fileno()]
    try: 
        to_conn.send(SOCKS_REQUEST_OK)
    except socket.error as e: 
        to_context["out_buffer"].write(SOCKS_REQUEST_OK) 
        return 
    context["status"] = STATUS_DATA
    to_context["status"] = STATUS_DATA 


def handle_redirect_data(context, text): 
    from_conn = context["from_conn"] 
    to_conn = context["to_conn"]
    in_buffer = context["in_buffer"]
    to_context = cons[to_conn.fileno()]
    to_out_buffer = to_context["out_buffer"] 
    crypted = context["crypted"] 
    #we don't read more until we can send them out 
    if to_out_buffer.tell(): 
        if to_out_buffer.tell() > 0x800000: 
            return 
        if not crypted:
            raw = text.translate(SD)
        else:
            raw = text.translate(DS)
        to_out_buffer.write(raw) 
        return 
    in_buffer.write(text) 
    while True: 
        try: 
            data = from_conn.recv(4096) 
            if not data:
                break
            in_buffer.write(data)
        except socket.error as e:
            if e.errno == errno.EAGAIN:
                break
            else:
                clean_queue(context["fd"])
                return 
    try: 
        data_count = in_buffer.tell() 
        if not crypted:
            raw = in_buffer.getvalue().translate(SD)
        else:
            raw = in_buffer.getvalue().translate(DS)
        data_sent = to_conn.send(raw) 
        if data_sent != data_count: 
            to_out_buffer.write(raw[data_sent:]) 
    except socket.error as e: 
        if e.errno == errno.EAGAIN: 
            if not crypted:
                raw = in_buffer.getvalue().translate(SD)
            else:
                raw = in_buffer.getvalue().translate(DS) 
            to_out_buffer.write(raw) 
        else: 
            clean_queue(context["fd"]) 
            return 
    in_buffer.truncate(0)
    return 


def handle_data(event, fd): 
    if fd in cons:
        context = cons[fd]
        context["fd"] = fd
    else:
        clean_queue(fd)
        return 

    status = context["status"]
    crypted = context["crypted"] 

    if event & EPOLLOUT:
        if context["out_buffer"].tell():
            handle_write_later(context) 
            return
        if status & STATUS_WAIT_REMOTE: 
            handle_remote_connected(context) 
            return

    if event & EPOLLIN: 
        if status & STATUS_HANDSHAKE: 
            handle_handshake(context) 
            return 
        result = which_status(context) 
        if result:
            status, text = result
        else:
            return 
        if status & STATUS_REQUEST: 
            handle_request(context, text) 
            return

        if status & STATUS_DATA: 
            handle_redirect_data(context, text)

def handle_connection(): 
    conn, addr = sock.accept() 
    fd = conn.fileno() 
    conn.setblocking(0)
    epoll_object.register(fd, EPOLLIN|EPOLLOUT) 
    cons[fd] = {
            "in_buffer": StringIO(),
            "out_buffer": StringIO(),
            "from_conn": conn,
            "to_conn": None,
            "crypted": True,
            "request": None,
            "status": STATUS_HANDSHAKE,
            "active":time()
            } 


def poll_wait():
    #if not has_in_event, make loop 10000 times slower
    has_in_event = True
    ep_poll = epoll_object.poll
    while 1: 
        if has_in_event:
            sleep_time = 0.000001
            has_in_event = False
        else:
            sleep_time = 0.01 
        sleep(sleep_time) 
        for fd, event in ep_poll(): 
            if fd == sockfd:
                if event & EPOLLIN:
                    handle_connection()
                else:
                    raise Exception("main socket error")
            else:
                handle_data(event, fd) 
            if event & EPOLLIN:
                has_in_event = True

if __name__ == "__main__": 
    server_config() 
    #run_as_user("quark") 
    #daemonize()
    poll_wait()
