#! /usr/bin/env python
#-*-encoding=utf-8-*-

import socket 
import os
import pdb
import errno 
import struct
import pwd 
import marshal 

from select import *
from fcntl import *
from struct import unpack
from struct import pack
from cStringIO import StringIO 
from time import sleep 
from time import time


#server ip, port 
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9988

MAX_LISTEN = 128
REMOTE = ("127.0.0.1", 9905)



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
SOCKS_REQUEST_OK_RAW = "\x05\x00\x00\x01%s%s" % (_inet_aton("0.0.0.0"), pack(">H", 8888))
SOCKS_REQUEST_OK = SOCKS_REQUEST_OK_RAW.translate(SD)


STATUS_HANDSHAKE = 0x1 << 1 
STATUS_REQUEST = 0x1 << 2
STATUS_WAIT_REMOTE = 0x1 << 3
STATUS_DATA = 0x1 << 4

STATUS_SERVER_HANDSHKAE = 0x1 << 5
STATUS_SERVER_REQUEST = 0x1 << 6 
STATUS_SERVER_CONNECTED = 0x1 <<7
STATUS_SERVER_WAIT_REMOTE = 0x1 << 8

log_file = open("client_log", "w+")


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
    #close pipe
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
    fd = context["fd"] 
    raw = from_conn.recv(128) 
    #maybe RST
    if not raw: 
        clean_queue(fd)
        return 
    if not raw.startswith("\x05\x01"): 
        print "weird handshake"
        clean_queue(fd)
        return
    #handshake packet or not 
    if len(raw) != 3: 
        clean_queue(fd)
        return
    #connect our server
    try:        
        request_sock = _socket(_AF_INET, _SOCK_STREAM)
        request_sock.setblocking(0)  
        request_fd = request_sock.fileno()
        epoll_object.register(request_fd, EPOLLIN|EPOLLOUT) 
    except Exception as e: 
        clean_queue(fd)
        return 
    #request context 
    cons[request_fd] = {
            "in_buffer": StringIO(),
            "out_buffer": StringIO(),
            "from_conn": request_sock,
            "to_conn": from_conn,
            "crypted": False, 
            "request": "",
            "status": STATUS_SERVER_CONNECTED,
            "active": time()
            } 
    context["to_conn"] = request_sock
    #next status , CONNECTED
    context["status"] = 0
    context["request"] = ""

    try: 
        request_sock.connect(REMOTE)
    except socket.error as e: 
        #close connection if it's a real exception
        if e.errno != errno.EINPROGRESS:
            clean_queue(fd) 


def which_status(context): 
    fd = context["fd"]
    from_conn = context["from_conn"] 
    status = None 
    try:
        text = from_conn.recv(256) 
    except socket.error: 
        clean_queue(context["fd"])
        return 
    #may RST
    if not text: 
        clean_queue(context["fd"])
        return 
    raw = text
    #if this msg if from server, decrypt it
    if not context["crypted"]: 
        raw = text.translate(DS)           
    if raw == "\x05\x00":
        status = STATUS_SERVER_HANDSHKAE 
    elif raw.startswith("\x05\x01\x00"):
        status = STATUS_REQUEST 
    elif raw.startswith("\x05\x00\x00\x01"): 
        status = STATUS_SERVER_WAIT_REMOTE 
    else:            
        status = STATUS_DATA 
    return status, text


def handle_server_connected(context): 
    try: 
        context["from_conn"].send(SOCKS_HANDSHAKE_CLIENT) 
    except socket.error: 
        context["out_buffer"].write(SOCKS_HANDSHAKE_CLIENT) 
        return  
    context["status"] = STATUS_SERVER_HANDSHKAE 


def handle_server_handshake(context): 
    try:
        context["to_conn"].send("\x05\x00")
    except socket.error:
        context["out_buffer"].write(SOCKS_HANDSHAKE_CLIENT)
        return
    #client may REQUEST 
    context["status"] = STATUS_REQUEST
    

def handle_new_request(context, text): 
    to_conn = context["to_conn"]
    to_context = cons[to_conn.fileno()] 
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
    addr_port = parse_buffer.read(2) 
    parse_buffer.close()
    addr_to += addr_port
    #maybe wrong status
    to_data = False
    try:
        port = unpack(">H", addr_port)
    except struct.error: 
        to_data = True 
    #change status to DATA if this packet is not a REQUEST
    if not to_data: 
        try:        
            to_conn.send(text.translate(SD)) 
        except socket.error as e: 
            if e.errno == errno.EAGAIN:
                to_context["out_buffer"].write(text.translate(SD))  
            return 
        remote = (addr, port[0]) 
        print "new request\n", remote
        context["request"] = remote
        to_context["request"] = remote
    else: 
        status = STATUS_DATA 


def handle_server_wait_remote(context): 
    to_conn = context["to_conn"]
    to_context = cons[to_conn.fileno()] 
    try: 
        to_conn.send(SOCKS_REQUEST_OK_RAW)
    except socket.error:
        to_context["out_buffer"].write(SOCKS_REQUEST_OK_RAW)
        return 
    context["status"] = STATUS_DATA
    to_context["status"] = STATUS_DATA 


def handle_redirect_data(context, text): 
    from_conn = context["from_conn"]
    to_conn = context["to_conn"]
    to_context = cons[context["to_conn"].fileno()]
    to_out_buffer = to_context["out_buffer"] 
    in_buffer = context["in_buffer"]
    crypted = context["crypted"] 
    #we don't read more until we can send them out
    if to_out_buffer.tell():
        if to_out_buffer.tell() > 0x800000: 
            return 
        if crypted:
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
        if crypted:
            raw = in_buffer.getvalue().translate(SD)
        else:
            raw = in_buffer.getvalue().translate(DS)
        data_sent = to_conn.send(raw) 
        if data_sent != data_count: 
            to_out_buffer.write(raw[data_sent:]) 
    except socket.error as e:
        if e.errno != errno.EAGAIN: 
            clean_queue(context["fd"])
            return
        if crypted:
            raw = in_buffer.getvalue().translate(SD) 
        else:
            raw = raw = in_buffer.getvalue().translate(DS)
        to_out_buffer.write(raw) 
    in_buffer.truncate(0) 


def handle_data(event, fd): 
    if fd in cons: 
        context = cons[fd] 
        context["fd"] = fd 
    else:
        clean_queue(fd) 
        return 

    status = context["status"] 

    if event & EPOLLOUT: 
        if status & STATUS_SERVER_CONNECTED: 
            handle_server_connected(context) 
            return
        if context["out_buffer"].tell(): 
            handle_write_later(context) 
            if not event & EPOLLIN:
                print "nothing"
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

        if status & STATUS_SERVER_HANDSHKAE: 
            handle_server_handshake(context)
            return 

        if status & STATUS_REQUEST: 
            handle_new_request(context, text) 
            return

        if status & STATUS_SERVER_WAIT_REMOTE: 
            handle_server_wait_remote(context)
            return 

        if status & STATUS_DATA: 
            handle_redirect_data(context, text)

def handle_connection(event): 
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
    #if not has_in_event, make loop 1000 times slower
    has_in_event = True
    ep_poll = epoll_object.poll
    while 1: 
        if has_in_event:
            sleep_time = 0.00001
            has_in_event = False
        else:
            sleep_time = 0.01 
        sleep(sleep_time) 
        for fd, event in ep_poll(1): 
            if event & EPOLLIN:
                has_in_event = True
            if fd == sockfd:
                handle_connection(event) 
            else:
                handle_data(event, fd) 

if __name__ == "__main__":
    server_config() 
    #daemonize()
    poll_wait()
