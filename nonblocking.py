import select
import socket
import os
import pdb
import errno 
import io 
import re 
import fcntl 
import signal
import pwd
import mmap
import traceback
import ujson
import _proc
import simple_http
import simple_gzip

from time import time 
from time import sleep
from simple_http import auto_content_type
from simple_http import parse_simple_post
from simple_http import parse_header
from socket import inet_ntoa
from struct import unpack
from cStringIO import StringIO
from errno import EAGAIN
from re import match as _match
from sys import exc_info

#consts 
cons = {}
buf_queue = {} 
applications = {}
forbidden = {} 
statics = {}
sucess = 0
failed = 0

epm = None
sock = None 
sock_fd = None
data_fd = None 
data_fifo = None


MAX_LISTEN  = 10240
KEEP_ALIVE = 60 
BODY_MAXLEN = 1*1024*1024


NONBLOCKING_LOG = "nonblocking.log" 
log_file = None 
LOG_ERR = 0x1 << 1
LOG_WARN = 0x1 << 2
LOG_INFO = 0x1 << 3
LOG_ALL = LOG_ERR | LOG_WARN | LOG_INFO
log_level = LOG_ALL
HTTP_LEVEL = 0x1 << 1
SERVER_LEVEL = 0x1 << 2

LOG_BUFFER_SIZE = 128*1024
log_buffer = None

STATICS_PRELOAD = 0x1 << 1
STATICS_MMAP = 0x1 << 2
STATICS_NORMAL = 0x1 << 3

COMMAND_IP_FORBIDDEN = 0x1 << 1
COMMAND_FLUSH_LOG = 0x1 << 2 

#http consts
HEADER_END = "\r\n\r\n"
NEWLINE = "\r\n" 
gzip_write = simple_gzip.write

#socket consts
_socket = socket.socket 
AF_INET = socket.AF_INET
SOCK_STREAM = socket.SOCK_STREAM
SOL_SOCKET = socket.SOL_SOCKET
SO_REUSEADDR = socket.SO_REUSEADDR
#epoll consts
EPOLLIN = select.EPOLLIN
EPOLLOUT = select.EPOLLOUT
EPOLLHUP = select.EPOLLHUP
EPOLLET = select.EPOLLET
EPOLLERR = select.EPOLLERR
#fcntl consts
_fcntl = fcntl.fcntl
F_SETFL = fcntl.F_SETFL
O_NONBLOCK = os.O_NONBLOCK

#file permisiion bits
permX = 0b001
permW = 0b010
permR = 0b100


site_allowed = [
        "localhost:80",
        "128.0.0.1:80"
        ]

refer_allowed = [
        "http://localhost:80",
        "http://127.0.0.1:80"
        ]

#CSP header
source_domain_allowed = {
        "default-src": [
            "http://localhost:80",
            "http://127.0.0.1:80"]
        }

csp_directive = (
    "default-src",
    "frame-src",
    "img-src",
    "script-src",
    "style-src",
    "media-src",
    "object-src",
    "connect-src")

#anti XSRF
default_header = {
    "Content-Type": "text/html",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block",
    "X-Content-Type-Options": "nosniff",
    "X-Content-Security-Policy": "default-src self; frame-src: self; img-src self; script-src self; style-src self; media-src self; object-src self; connect-src:self"
    }

def set_domain_allowed(policy):
    if not isinstance(policy, dict):
        raise Exception("domains must be a dict") 
    policy_list = []
    for rule in policy:    
        if rule not in csp_directive:
            continue
        policy_list.extend((rule, "\x20")) 
        for value in policy[rule]: 
            policy_list.extend((value, "\x20"))
        policy_list.append(";") 
    default_header["X-Content-Security-Policy"] = "".join(policy_list) 

def set_refer_allowed(refers):
    global refer_allowed 
    if not isinstance(refers, list):
        raise Exception("refers must be a list") 
    for i in refers:
        if "\x20" in i:
            raise Exception("space is not allowed in refer")
    refer_allowed = refers

def sigint_handler(signum, frame): 
    poll_close() 
    _proc.force_exit(0)

def sigtimer_handler(signum, frame):
    #clean keep-alive every KEEP_ALIVE seconds
    now = time() 
    for fd in buf_queue.keys(): 
        if now > buf_queue[fd][-4]: 
            clean_queue(fd) 

def sigusr1_handler(signum, frame):
    print "server status: sucess: %d, failed: %d" % (sucess, failed)

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
    global log_file, log_buffer 
    global data_fd, data_fifo
    #SIGINT clean up and quit
    signal.signal(signal.SIGINT, sigint_handler) 
    #keep alive timer
    signal.signal(signal.SIGALRM, sigtimer_handler)
    signal.setitimer(signal.ITIMER_REAL, KEEP_ALIVE, KEEP_ALIVE)
    #syscall interrupt: restart 
    signal.siginterrupt(signal.SIGALRM, False)
    signal.siginterrupt(signal.SIGUSR1, False)
    #server status
    signal.signal(signal.SIGUSR1, sigusr1_handler)
    #data channel
    data_fifo = "nonblocking_pid_%d.fifo" % os.getpid()
    os.mkfifo(data_fifo , 0666) 
    f = open(data_fifo, "r+")
    data_fd = os.dup(f.fileno())
    f.close()
    #main log
    if os.path.exists(NONBLOCKING_LOG): 
        log_file = open(NONBLOCKING_LOG, "a+")
    else:
        log_file = open(NONBLOCKING_LOG, "w")
    if LOG_BUFFER_SIZE:
        log_buffer = StringIO()
    

def poll_open(connection):
    global epm, sock, sock_fd 
    #epoll and socket
    epm = select.epoll()
    sock = _socket(AF_INET, SOCK_STREAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) 
    sock_fd = sock.fileno() 
    sock.bind(connection)
    sock.listen(MAX_LISTEN) 
    epm.register(sock_fd, EPOLLIN | EPOLLERR | EPOLLHUP)
    epm.register(data_fd, EPOLLIN|EPOLLERR) 


def poll_close(): 
    global epm, sock 
    log_file.write("pid: %d sigint, exit\n" % os.getpid())
    if log_buffer: 
        log_file.write(log_buffer.getvalue())
        log_buffer.close() 
    log_file.close() 
    sock.close() 
    try:
        epm.unregister(data_fd) 
        os.close(f) 
    except:
        pass 
    epm.close()
    try:
        os.remove(data_fifo)
    except:
        pass

def handle_new_connection(connection):
    con, addr = connection
    #don't accept ip in forbidden
    if addr[0] in forbidden:
        try:
            con.shutdown(socket.SHUT_RDWR)
        except:
            pass
        con.close()
        return
    incoming_fd = con.fileno()
    epm.register(incoming_fd,
            EPOLLIN | EPOLLOUT |EPOLLET | EPOLLERR | EPOLLHUP) 
    _fcntl(incoming_fd, F_SETFL, O_NONBLOCK)
    cons[incoming_fd] = (con, addr)


def log_err(args): 
    final = None
    if len(args) < 3:
        final = str(args) 
    if not final:
        traceback = args[2]
        final = "error: %s line: %d, file: %s" % (
                str(traceback[1]),
                traceback[2].tb_lineno,
                traceback[2].f_code.co_filename) 
    if log_buffer:
        log_buffer.write(final+"\n") 
        if log_buffer.tell() >= LOG_BUFFER_SIZE:
            log_file.write(log_buffer.getvalue()) 
            log_buffer.truncate(0) 
    else:
        log_file.write(final+"\n")
    log_file.flush() 


def handle_events(events_list): 
    has_in_event = False
    for fd, event in events_list: 
        if fd == sock_fd: 
            if events & (EPOLLERR | EPOLLHUP):
                raise Exception("main socket error") 
            handle_new_connection(sock.accept())
            continue 
        try: 
            handle_http_request(fd, event) 
        except Exception as err: 
            args = err.args
            if log_level & LOG_ERR: 
                log_err(args)
            if len(args) == 3:
                if fd not in cons:    
                    continue
                handle_server_error(fd, args)
        if event & EPOLLIN:
            has_in_event = True
    return has_in_event
         
def poll_wait(): 
    global sucess, failed 
    has_in_event = True 
    while True: 
        if has_in_event:
            sleep_time = 0
            has_in_event = False
        else:
            sleep_time = 0.001
        sleep(sleep_time) 
        try:
            events_list = epm.poll(1)
        except IOError as e:
            continue 
        try:
            has_in_event = handle_events(events_list)
            sucess += 1
        except Exception as e:
            log_err(e.args)
            failed += 1


def clean_queue(fd): 
    if fd not in cons:
        epm.unregister(fd)
        os.close(fd)
    con, addr= cons[fd]
    #maybe tcp RST
    try:
        con.shutdown(socket.SHUT_RDWR) 
    except socket.error, err: 
        print err
    #release connection
    con.close() 
    #remove it from queue
    del cons[fd]
    #delete it's context
    del buf_queue[fd] 
    #remove tits fd from epoll
    try:
        epm.unregister(fd)
    except OSError, err:
        print err 

def install(app):
    if not isinstance(app, dict):
        raise Exception("%s should be a dictionary" % app)
    if not app.get("url"):
        raise Exception("no url specified in %s" % app)
    #precompiled regex
    applications[re.compile(app["url"])] = app    

    
def uninstall(url):    
    if not isinstance(url, str) and not isinstance(url, unicode):
        raise Exception("url should be a string")
    if not applications.get(url):
        del applications[url]


def load_file(args, d, f): 
    topdir, path, mode = args
    prefix_path = "/%s/%s" % (d.replace(path, topdir), f)
    if mode & STATICS_PRELOAD:
        itsname = "%s/%s" % (d, f)
        itsfile = open(itsname, "r") 
        return (prefix_path,
                f, itsfile.read(), None)
        itsfile.close()
    elif mode & STATICS_MMAP:
        itsname = "%s/%s" % (d, f)
        itsfile = open(itsname, "r+")
        size = os.stat(itsname).st_size
        itsmap = mmap.mmap(itsfile.fileno(), 0, mmap.MAP_SHARED)
        itsfile.close() 
        return (prefix_path, f, itsmap, size)
    elif mode & STATICS_NORMAL:
        return (f, None, None)


def scan_statics(*args): 
    topdir, path, mode = args
    if path.startswith("."):
        raise Exception("absolute path only") 
    for d, subs, files in os.walk(path): 
        for f in files:    
            yield load_file(args, d, f)

def install_statics(topdir, path, mode): 
    for url, name, value, size in scan_statics(topdir, path, mode): 
        if url not in statics: 
            statics[url] = (mode, name, value, size)
        else:
            raise Exception("name collsion: %s" % name)

def uninstall_statics(topdir):
    for k in statics.keys():
        if k.startswith(topdir):
            del statics[k]

#server internal error
def handle_server_error(fd, args): 
    code = args[0] 
    if (len(args) != 3) or (not isinstance(code, int)):
        return
    error_header = default_header.copy() 
    error_header["status"] = code 
    response = {}
    if code == 500:
        response.update({
                "header": error_header,
                "stream": ""
                })
    elif code == 503:
        response.update({
            "header": error_header,
            "stream": ""
            })
    elif code == 400:
        response.update({
                "header": error_header,
                "stream": ""
                }) 
    else:
        response.update({
            "header": error_header,
            "stream": ""
            })
    outgoing_buf = StringIO()
    write_response(response, outgoing_buf) 
    try:
        cons[fd][0].sendall(outgoing_buf.getvalue())
    except socket.error:
        pass
    outgoing_buf.close()
    clean_queue(fd)

def handle_http_error(request, response):
    code = response["header"]["status"] 
    if code == 400: 
        response.update({ 
            "stream": "Page Not Found"
            }) 
    if log_level & LOG_INFO:        
        if log_buffer:
            log_buffer.write(ujson.dumps(request)+"\n") 
            if log_buffer.tell() >= LOG_BUFFER_SIZE:
                log_file.write(log_buffer.getvalue())
                log_buffer.truncate(0)
        else: 
            log_file.write(ujson.dumps(request)+"\n")
        log_file.flush()

def static_handler(request, response): 
    path = request["header"]["path"]
    res = statics[path]
    mode = res[0]
    name = res[1] 
    #raw string
    if mode == STATICS_PRELOAD:
        response.update({
                "header": {
                    "status": 200,
                    "Content-Type": auto_content_type(name)
                    },
                "stream": res[2]
                })
    #file
    elif mode == STATICS_NORMAL: 
        f = open(name, "r")
        response.update({
            "header": {
                "status": 200,
                "Content-Type": auto_content_type(name)
                },
            "stream": f.read()
            })
        f.close() 
    elif mode == STATICS_MMAP:
        itsmap = res[2]
        response.update({
                "header": {
                    "status": 200,
                    "Content-Type": auto_content_type(name)
                    },
                "stream": itsmap.read(res[3])
                }) 
        itsmap.seek(0, io.SEEK_SET) 

def url_handler(request, response): 
    header = request["header"]
    url = header.get("path", "/")
    method = header["method"]
    response["header"] = default_header.copy()
    match = False 
    for pattern in applications:
        if pattern.match(url):
            match = True
            app_dict = applications[pattern]
            if method not in app_dict:
                raise Exception((HTTP_LEVEL,
                    400, None, "Method not allowed"))
            try: 
                app_dict[method](request, response)
            except Exception, err: 
                if len(err.args) != 4:
                    raise err
                level = err.args[0]
                if level & HTTP_LEVEL:
                    handle_http_error(request, response)
                    match = True 
            break 
    if not match:
        #maybe statics
        if url in statics:
            match = True 
            try:
                static_handler(request, response)
            except Exception, err: 
                if len(err.args) != 4:
                    raise err
                if err.args[0] & HTTP_LEVEL:
                    handle_http_error(request, response)
                    match = True
    #application error
    if not match: 
        response.update({
            "header": {
                "status": 400
                },
            "stream": ""
            })
        handle_http_error(request, response) 
    return response

def write_response(response, outgoing_buf): 
    content_buf = StringIO()
    #gzip stream
    header = response["header"] 
    if "Vary" in header:
        header["Vary"] += ", Accept-Encoding"
    else:
        header["Vary"] = "Accept-Encoding"
    if "gzip" in header.get("Content-Encoding", ""): 
        gzip_write(response["stream"], content_buf) 
    else:
        content_buf.write(response["stream"]) 
    header["Content-Length"] = str(content_buf.tell())
    #add cookie to header 
    if "cookie" in response:
        cookie = simple_http.unparse_full_cookie(response["cookie"])
        header["Set-Cookie"] = cookie 
    data = simple_http.unparse_header(header, False) 
    #write header and content 
    outgoing_buf.write("".join((data, NEWLINE, content_buf.getvalue()))) 
    content_buf.close()


def handle_message(fd, events): 
    command = ord(os.read(fd, 1))
    #add forbidden ip 
    if command & COMMAND_IP_FORBIDDEN:
        try:
            many = unpack("I", os.read(fd, 4))[0] 
            for i in range(many):
                ipstr = os.read(fd, 4)
                forbidden[inet_ntoa(ipstr)] = None 
        except Exception, err: 
            if log_level & LOG_WARN:
                log_file.write(ujson.dumps(err.args)+"\n")
            return
        return 
    if command & COMMAND_FLUSH_LOG: 
        if log_buffer:
            log_file.write(log_buffer.getvalue()) 
            log_buffer.truncate(0)
        log_file.flush()
        return

def handle_http_request(fd, events): 
    #close connection on error or hup 
    if events & (EPOLLERR|EPOLLHUP): 
        clean_queue(fd)
        return 
    #maybe our data_fd
    if fd == data_fd:
        if events & EPOLLIN:        
            handle_message(fd, events)
        else:
            return
    
    con, addr = cons[fd] 
    #if we have accepted tits ip, close connection.
    if addr[0] in forbidden:
        raise Exception((HTTP_LEVEL, 403, exc_info()))
    #default Connection: Close
    close_request = True
    #http request context queue 
    if fd not in buf_queue:
        incoming_buf = StringIO()
        outgoing_buf = StringIO()
        left = 0 
        write_later = 0
        post_type = 0
        buf_queue[fd] = [incoming_buf, outgoing_buf, None, None, False, time()+KEEP_ALIVE, 0, 0, 0] 
    else: 
        context = buf_queue[fd] 
        incoming_buf, outgoing_buf, header, cookie, close_request, alive, post_type, write_later, left = context
        #update keep-alive time 
        context[-4] = time() + KEEP_ALIVE 
    #read all we got 
    if events & EPOLLIN: 
        #with write_later, we have to deny new request
        if write_later:
            raise Exception((SERVER_LEVEL,
                503, exc_info()))
        while True: 
            try:
                data = os.read(fd, 4096) 
                #tcp FIN
                if not data: 
                    clean_queue(fd)
                    return
                incoming_buf.write(data)
            except OSError as e: 
                if e.errno != EAGAIN:
                    raise e 
                break 
    #maybe heavy traffic 
    if events & EPOLLOUT:
        if write_later: 
            #try 3 times
            if write_later > 2:
                raise Exception((SERVER_LEVEL,
                    500, exc_info()))
            #maybe avavible 
            try:
                os.write(fd, outgoing_buf.getvalue())
            except OSError as e:
                if e.errno != EAGAIN:
                    raise e
                #still unavaiable 
                #add write_later
                context[-2] += 1
                return 
            #finally
            if close_reqest:
                incoming_buf.close()
                outgoing_buf.close()
                clean_queue(fd)
                return
            else:
                incoming_buf.truncate(0)
                outgoing_buf.truncate(0) 
                #write_later = 0
                context[-2] = 0
        else:
            #EPOLLOUT without EPOLLIN, ignore
            if not events & EPOLLIN:
                return 
    #handle this chunk 
    if not left: 
        data = incoming_buf.getvalue()
        header_end = data.find(HEADER_END)            
        if header_end < 0:
            #max header length
            incoming_buf.close()
            raise Exception((SERVER_LEVEL,
                503, exc_info()))
        try:
            header, cookie = parse_header(data[:header_end]) 
        except:
            raise Exception((HTTP_LEVEL,
                400, None, "unable to find header")) 
        if header.get("Connection") == "keep-alive": 
            close_reqest = False 
        if header.get("method") == "GET": 
            #build_request 
            request = {
                    "header": header,
                    "cookie": cookie
                    } 
            request["client"] = addr
            request["fd"] = fd
            #get response
            response = {} 
            response = url_handler(request, response) 
            if close_request:
                response["header"]["Connection"] = "close"
            write_response(response, outgoing_buf)
            #write response to network.
            try:
                os.write(fd, outgoing_buf.getvalue())
            except OSError as e:
                if e.errno == EAGAIN:
                    raise e 
                #write later
                context[-2] += 1 
                return
            if close_request:
                incoming_buf.close()
                outgoing_buf.close()
                clean_queue(fd)
                return
            else:
                incoming_buf.truncate(0)
                outgoing_buf.truncate(0) 
        elif header.get("method") == "POST": 
            try:
                content_length = int(header.get("Content-Length"))
            except:
                raise Exception((HTTP_LEVEL,
                    400, None, "no Content-Lenght in header"))
            incoming_buf.seek(0, io.SEEK_END)
            left = incoming_buf.tell() - (header_end+4)
            #remove header from post stream
            incoming_buf.truncate(0)
            incoming_buf.write(data[header_end+4:]) 
            if incoming_buf.tell() > BODY_MAXLEN:
                raise Exception((HTTP_LEVEL,
                    400, None, "Body too big"))
            if left < content_length: 
                #wait request body
                request = context 
                request[-1] = content_length - left 
                request[2] = header
                request[3] = cookie
                request[4] = close_reqest
                request[-3] = post_type
            else: 
                if "Content-Type" in header: 
                    #form post 
                    ct = header.get("Content-Type")
                    if "x-www-form-urlencoded" in ct:
                        post_type = 0 
                    elif "multipart/form-data" in ct: 
                        post_type = 1
                    else:
                        raise Exception((HTTP_LEVEL,
                            400, None, "Unkown post type"))
                else:
                    raise Exception((HTTP_LEVEL,
                        400, None, "No Content-Type in header"))
                if "Content-Length" not in header:
                    raise Exception((HTTP_LEVEL,
                        400, None, "No Content-Length in header")) 
                #build request
                request = {
                        "header": header,
                        "cookie": cookie
                        }
                request["client"] = addr
                request["fd"] = fd
                #handle request 
                response = {}
                if post_type == 0:
                    if content_length: 
                        request["stream"] = parse_simple_post(incoming_buf.getvalue())
                    else:
                        request["stream"] = {}
                elif post_type == 1: 
                    bend = ct.find("boundary")
                    if bend < 0:
                        raise Exception((HTTP_LEVEL,
                            400, None, "No boundary in multi-part post"))
                    else:
                        boundary = ct[bend+9:]
                    if content_length:
                        request["stream"] = parse_complex_post(incoming_buf.getvalue(), boundary) 
                    else:
                        request["stream"] = {}
                else:
                    request["stream"] = {}
                response = url_handler(request, response)
                #write response to buffer
                write_response(response, outgoing_buf)
                #write response to network
                try:
                    os.write(fd, outgoing_buf.getvalue())
                except OSError as e:
                    if e.errno == EAGAIN:
                        raise e
                    #write later
                    print "write later"
                    context[-2] += 1
                    return
                if close_request:
                    incoming_buf.close()
                    outgoing_buf.close()
                    clean_queue(fd)
                    return
                else:
                    incoming_buf.truncate(0)
                    outgoing_buf.truncate(0) 

    else:       
        #handle unfinished post
        left = content_length - incoming_buf.seek(0, io.SEEK_END)
        if incoming_buf.tell() > BODY_MAXLEN:
            raise Exception((HTTP_LEVEL,
                400, None, "Body too big"))
        if left > 0:
            context[-1] = left
        else:
            request = {
                    "header": header,
                    "cookie": cookie
                    } 
            request["client"] = addr
            request["fd"] = fd
            if post_type == 0: 
                request["stream"] = parse_simple_post(incoming_buf.getvalue())
            elif post_type == 1: 
                bend = ct.find("boundary")
                if bend < 0:
                    raise Exception((HTTP_LEVEL, 400,
                        None, "No boundary in multi-part post"))
                else:
                    boundary = ct[bend+9:]
                request["stream"] = parse_complex_post(incoming_buf.getvalue(), boundary) 
            else:
                request["stream"] = {} 
            response = {}
            response = url_handler(request, response) 
            write_response(response, outgoing_buf)
            try:
                os.write(fd, outgoing_buf.getvalue())
            except OSError as e:
                if e.errno == EAGAIN:
                    raise e
                context[-2] += 1
                return
            if close_request:
                incoming_buf.close()
                outgoing_buf.close()
                clean_queue(fd)
                return
            else:
                incoming_buf.truncate(0)
                outgoing_buf.truncate(0) 
