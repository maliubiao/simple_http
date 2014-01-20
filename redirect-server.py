import socket 
import os
import pdb
import errno 
import struct

#alias 
from select import *
from fcntl import *
from struct import unpack
from struct import pack
from cStringIO import StringIO
from Crypto.Cipher import AES 
from time import sleep 
from time import time

#server ip, port
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999 

MAX_LISTEN = 10

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
_accept = None

sockfd = None
ep = None
cons = {} 


def align_KEY(KEY):
    len_KEY = len(KEY)
    if len_KEY < 8:
        return align_KEY(KEY*2)
    if len_KEY < 16:
        return KEY + KEY[:(16 - len_KEY)]
    if len_KEY < 24:
        return KEY + KEY[:(24 - len_KEY)]
    if len_KEY < 32:
        return KEY + KEY[:(32 - len_KEY)]
    return KEY


def server_config():
    global sockfd, ep, _accept
    sock = _socket(_AF_INET, _SOCK_STREAM) 
    sock.setsockopt(_SOL_SOCKET, _SO_REUSEADDR, 1)
    sock.bind((SERVER_IP, SERVER_PORT)) 
    sock.listen(MAX_LISTEN) 
    _accept = sock.accept 
    sock.setsockopt(_SOL_SOCKET, _SO_REUSEADDR, 1) 
    sockfd = sock.fileno() 
    ep = epoll()
    ep.register(sockfd, EPOLLIN | EPOLLERR | EPOLLHUP) 


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
    if server:
        context_server = cons[server_fd]
    #close client buffer
    context_client["in_buffer"].close()
    context_client["out_buffer"].close()
    if server:
        #close server buffer
        context_server["in_buffer"].close()
        context_server["out_buffer"].close()
    #close client socket
    from_conn = context_client["from_conn"]
    try:
        from_conn.shutdown(socket.SHUT_RDWR) 
    except:
        pass
    ep.unregister(fd) 
    from_conn.close() 
    if server:
        #close server socket
        from_conn = context_server["from_conn"]
        try: 
            from_conn.shutdown(socket.SHUT_RDWR) 
        except: 
            pass
        ep.unregister(from_conn) 
        from_conn.close() 
        del cons[server_fd]
    #delete context
    del cons[fd] 




STATUS_HANDSHAKE = 0x1 << 1 
STATUS_REQUEST = 0x1 << 2
STATUS_WAIT_REMOTE = 0x1 << 3
STATUS_DATA = 0x1 << 4

status_dict = {
    STATUS_HANDSHAKE: "status-handshake",
    STATUS_REQUEST: "status-request",
    STATUS_WAIT_REMOTE: "status-remote",
    STATUS_DATA: "status-data",
    0: "status-clear"
}

f = open("logger.log", "w")

def write_log(msg):
    f.write(msg)
    f.flush()

def handle_data(event, fd):
    #epoll event after clean_queue
    if fd not in cons:
        clean_queue(fd)
        return 
    #lazy unpack context
    context = cons[fd] 
    crypted, status, from_conn, to_conn, in_buffer, active, out_buffer, request = context.values() 
    
    if status & STATUS_HANDSHAKE:
        if out_buffer.tell() and event & EPOLLOUT:
            try:
                from_conn.sendall(out_buffer.getvalue()) 
            except socket.error:
                if not (event & EPOLLIN):
                    return
            out_buffer.truncate(0)
            context["status"] = STATUS_REQUEST
            return 
        if event & EPOLLIN: 
            try:
                raw = from_conn.recv(128)
            except OSError:
                return
            #maybe RST
            if not raw:
                clean_queue(fd)
                return 
            if not raw.startswith("\x05\x01"): 
                print "weird handshake"
                clean_queue(fd)
                return
            #handshake packet or not
            if len(raw) == 3:
                try: 
                    from_conn.sendall("\x05\x00") 
                except socket.error: 
                    out_buffer.write(towrite) 
                    return  
                context["status"] = STATUS_REQUEST
                return
            else:
                clean_queue(fd)
                return 

    if event & EPOLLIN: 
        try:
            text = from_conn.recv(64) 
        except socket.error:
            return 
        #may RST 
        if not text:
            clean_queue(fd)
            return 
        if not text.startswith("\x05\x01\x00"):
            status = STATUS_DATA 
        else:            
            status = STATUS_REQUEST 
    if status & STATUS_REQUEST: 
        if not (event & (~EPOLLOUT)):
            return 
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
                ep.register(request_fd, EPOLLIN|EPOLLOUT|EPOLLET) 
            except Exception as e: 
                clean_queue(fd)
                return 
            #request context 
            remote = (addr, port[0]) 
            cons[request_fd] = {
                    "in_buffer": StringIO(),
                    "out_buffer": StringIO(),
                    "from_conn": request_sock,
                    "to_conn": from_conn,
                    "crypted": True, 
                    "request": remote,
                    "status": STATUS_WAIT_REMOTE,
                    "active": time()
                    } 
            context["to_conn"] = request_sock
            context["status"] = STATUS_WAIT_REMOTE
            context["request"] = remote
            try: 
                request_sock.connect(remote)
            except socket.error as e: 
                #close connection if it's a real exception
                if e.errno != errno.EINPROGRESS:
                    clean_queue[fd] 
            return
        else: 
            status = STATUS_DATA 

    if status & STATUS_WAIT_REMOTE: 
        if not (event & EPOLLOUT):
            return
        if out_buffer.tell():
            try:
                from_conn.sendall(out_buffer.getvalue())
            except socket.error:
                if not (event & EPOLLIN):
                    return
            out_buffer.truncate(0)
            context["status"] = STATUS_DATA
            return 
        msg = "\x05\x00\x00\x01%s%s" % (_inet_aton("0.0.0.0"),
                pack(">H", 8888)) 
        try: 
            to_conn.sendall(msg)
        except socket.error:
            out_buffer.write(msg)
            return 
        context["status"] = STATUS_DATA
        cons[to_conn.fileno()]["status"] = STATUS_DATA 

    if status & STATUS_DATA:
        if out_buffer.tell() and event & EPOLLOUT:
            try:
                from_conn.sendall(out_buffer.getvalue())
            except socket.error:
                return               
            out_buffer.truncate(0)
            return
        if event & EPOLLIN: 
            in_buffer.write(text) 
            while True:
                try:
                    data = from_conn.recv(4096) 
                except socket.error as e: 
                    if e.errno == errno.EAGAIN:
                        break
                    else:
                        clean_queue(fd)
                        return
                if data:
                    in_buffer.write(data)
                else:
                    break 
            try:
                to_conn.sendall(in_buffer.getvalue()) 
            except Exception:
                clean_queue(fd)
                return 
            in_buffer.truncate(0) 

def handle_connection():
    conn, addr = _accept() 
    fd = conn.fileno() 
    conn.setblocking(0)
    ep.register(fd, EPOLLIN|EPOLLOUT|EPOLLET)
    #add fd to queue
    cons[fd] = {
            "in_buffer": StringIO(),
            "out_buffer": StringIO(),
            "from_conn": conn,
            "to_conn": None,
            "crypted": False,
            "request": None,
            "status": STATUS_HANDSHAKE,
            "active":time()
            } 

def poll_wait():
    while True:
        for fd, event in ep.poll(): 
            if fd == sockfd:
                if event & EPOLLIN:
                    handle_connection()
                else:
                    raise Exception("main socket error")
            else:
                handle_data(event, fd)

if __name__ == "__main__":
    server_config()
    poll_wait()
