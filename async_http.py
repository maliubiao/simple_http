#-*-encoding=utf-8-*-
#! /usr/bin/env python
from _http import *

import ctypes
import socket
import os
import sys
import struct
import pwd
import marshal 
import string
import pdb
import errno 
import pprint
import io
import random 
import time
import traceback

from cStringIO import StringIO 

from select import * 


def get_random():
    return os.urandom(8).encode("hex")


def random_header():
    h = default_header.copy()
    h["isp-tracker"] = get_random()
    return h 



def genua_firefox(): 
    v = random.choice(b_ver["firefox"]) 
    os = random.choice(os_str["firefox"])
    return base_agents["firefox"] % (os % v, v)   


def genua_mac():
    return base_agents["safari"] % random.choice(b_ver["safari"])
    


def genua_opera(): 
    return base_agents["opera"] % random.choice(b_ver["opera"])


ua_tps = {
        "firefox": genua_firefox, 
        "safari": genua_mac,
        "opera": genua_opera
        }


base_agents = {
        "firefox": "Mozilla/5.0 (%s) Gecko/20100101 Firefox/%s.0",
        "opera": "Opera/9.80 (Windows NT 6.1; U; zh-cn) Presto/2.12.388 Version/11.%s",
        "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_1; zh-cn) AppleWebKit/537.22.1 (KHTML, like Gecko) Version/7.0.3 Safari/534.%s.1"
        } 


os_str = {
        "firefox": (
        "Windows NT 6.3; rv: %s.0",
        "Macintosh; Intel Mac OS X 10_10; rv: %s.0",
        "X11; Linux x86_64; rv: %s.0",
        ) 
        }


b_ver = {
    "firefox": range(9, 33), 
    "opera": range(1, 62),
    "safari": range(1, 53),
    }


def random_useragent():
    ua = random.choice(ua_tps.keys())
    return ua_tps[ua]() 


def nope_parser(body): 
    pass


fd_task = { }

tasks = { }

g = globals() 

debug = False


config = {
        "limit": 20, 
        "timeout": 30,
        "interval": 1,
        "retry": True,
        "retry_limit": 10, 
        } 


failed_tasks = { } 


internal_keys = set(("con",
"recv",
"send",
"status",
"fd", 
"random",
"start",
"res_status",
"res_cookie",
"res_header",
"text", 
"why",
"reason",
"header_only"
"chunked_idx",
"chunked_b",
))


possible_methods = set(("GET",
"POST",
"HEAD",
"PUT",
"DELETE")) 



def default_copy(task): 
    t = {} 
    for i in task:
        if i not in internal_keys:
            t[i] = task[i]
    return t 


def generate_request(task): 
    assert task["url"] and task["method"].upper() in possible_methods
    url = task["url"]
    rl = []
    url_parts = urlparse(url) 
    if task.get("query"):
        url_parts["query"] = generate_query(task["query"]) 
    if "header" in task:
        if not task["header"]:
            header = default_header.copy()
        else:
            header = task["header"]
    else:
        header = default_header.copy() 
    host = url_parts["host"]
    if "port" in url_parts:
        port = int(url_parts["port"])
        header["Host"] = "%s:%d" % (host, port) 
    else:
        port = 80 
        header["Host"] = host
    if url_parts.get("schema") == "https":
        task["ssl"] = True 
        port = 443
    else:
        task["ssl"] = False
    if "port" in url_parts:
        port = int(url_parts["port"])
    #没代理
    if not task.get("proxy"): 
        del url_parts["schema"] 
        del url_parts["host"]
        if "port" in url_parts:
            del url_parts["port"] 
    else:
        #有代理更新, 连接点换成代理
        pd = urlparse(task["proxy"])
        if pd["schema"] in "https":
            host = pd["host"]
            port = int(pd["port"])
        else:
            raise Exception("不支持的代理格式") 
    #不处理fragment
    if "fragment" in url_parts:
        del url_parts["fragment"] 
    path = generate_url(url_parts)
    method = task.get("method", METHOD_GET).upper()
    if method not in possible_methods:
        raise ValueError("unsupported method: %s" % method) 
    if method in ("POST", "PUT"):
        content = generate_post(header, task["payload"]) 
        header["Content-Length"] = str(len(content)) 
    rl.append(generate_request_header(header, method, path))
    if task.get("cookie"):
        rl.append("Cookie: ")
        rl.append(generate_cookie(task["cookie"]))
        rl.append(HEADER_END)
    else:
        rl.append("\r\n") 
    if method in ("POST", "PUT"): 
        rl.append(content)
    body = "".join(rl) 
    return (host, port), body 



#dns缓存
dns_buffer = {}

def set_dns_buffer(hosts):
    for i in hosts:
        d = urlparse(i) 
        if "port" in d:
            port = int(d["port"])
        else:
            port = 80 
        host = d["host"]
        start = time.time()
        ret = socket.getaddrinfo(host, port)
        cost = time.time() - start
        if cost > 1:
            print "dns slow query: %s, %s" % (cost, host)
        if not len(ret):
            raise socket.error("dns query failed: %s" % host)
        dns_buffer["%s:%s" %(host, port)] = ret[0][-1]


def auto_redirect(task): 
    task["redirect"] = task["redirect"] - 1 
    l1 = task["res_header"].get("Location")
    if not l1:
        l1 = task["res_header"].get("location") 
    if not l1:
        log_with_time("redirect without a location: %s" % str(task["url"]))
        return
    log_with_time("redirect to: %s" % l1) 
    urlsset = task["urlsset"]
    if l1 in urlsset: 
        urlsset[l1] += 1
    else:
        urlsset[l1] = 1 
    if urlsset[l1] > 3 or len(urlsset) > 10:
        log_with_time("endless redirect: %s" % l1)
        remove_task(task, why="endless redirect")
        return
    if not "cookie" in task:
        task["cookie"] = {} 
    task["cookie"].update(get_cookie(task["res_cookie"])) 
    task["url"] = l1
    insert_task(task) 



def call_chain_filter(task): 
    flt = chain_next(task)
    if not flt: 
        return 
    next = flt(task) 
    insert_task(next) 


def assign_key(d1, d2, *keys):
    for key in keys:
        if key in d2:
            d1[key] = d2[key] 


def call_parser(task): 
    res_header = task["res_header"] 
    status = task["res_status"]["status"]
    if task["redirect"] > 0 and 400 > status > 300: 
        auto_redirect(task)
        return 
    if task.get("chain"):
        if call_chain_filter(task): 
            return 
        prev = task["prev"] 
        assign_key(prev, task, 
                "res_status", "res_cookie",
                "res_header", "recv") 
        task = prev 
    enc =  task["res_header"].get("Content-Encoding") 
    text = task["recv"].getvalue() 
    task["recv"].truncate(0) 
    task["text"] = text 
    if enc == "gzip": 
        task["text"] = zlib.decompress(text, 16+zlib.MAX_WBITS)
    elif enc == "deflate": 
        task["text"] = zlib.decompress(text, -zlib.MAX_WBITS) 
    try:
        task["parser"](task) 
    except:
        traceback.print_exc()
        exit(1)



def decode_chunked(task): 
    normal = StringIO()
    try:
        convert_chunked(task["recv"], normal) 
    except Exception as e: 
        remove_task(task, why="chunked: %s" % e)
        return 
    task["recv"].close()
    task["recv"] = normal 




def convert_chunked(cbuf, normal_stream): 
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
        if len(chunk) != x:
            break
        cbuf.seek(2, io.SEEK_CUR)
        normal_stream.write(chunk) 



def decode_chunk_stream(task):
    goout = False
    b = task["chunked_b"]
    recv = task["recv"]
    done = False 
    recv_end = recv.tell() 
    recv.seek(task["chunked_idx"], io.SEEK_SET) 
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
        try:
            x = int(num, 16) 
        except: 
            f = open("chunk_bug." + str(time.time()), "w+")
            log_with_time("chunk_bug")
            f.write(task["recv"].getvalue())
            f.close()
            exit(1)
        if not x: 
            done = True
            break
        chunk = recv.read(x) 
        if len(chunk) != x:
            recv.seek(back_idx, io.SEEK_SET)
            break 
        recv.seek(2, io.SEEK_CUR) 
        b.write(chunk) 
    task["chunked_idx"] = recv.tell()
    recv.seek(recv_end, io.SEEK_SET)
    if done: 
        task["recv"] = task["chunked_b"] 
        del task["chunked_b"] 
        del task["chunked_idx"]
        call_parser(task) 
        remove_task(task)   

    


def parse_http_buffer(task): 
    header = task.get("res_header")
    if not header: 
        parse_header(task)
        header = task.get("res_header")
    if not header:
        remove_task(task)
        return
    if header.get("Transfer-Encoding") == "chunked":
        decode_chunked(task)
    call_parser(task) 
    remove_task(task)   



def parse_header(task): 
    recv = task["recv"]
    content = recv.getvalue()
    body_pos = content.find("\r\n\r\n") 
    if body_pos < 0:
        return 
    recv.truncate(0)
    recv.write(content[body_pos+4:]) 
    try:
        status, cookie, header = parse_response_header(content[:body_pos]) 
        task["res_cookie"] = cookie
        task["res_header"] = header
        task["res_status"] = status
    except (IndexError, TypeError) as e: 
        remove_task(task, why="解析http头失败: %s" % e)
        return 
    if task["header_only"]:
        call_parser(task)
        remove_task(task)
        return
    task["status"] = STATUS_HEADER 


def parse_response(header, task): 
    #检测请求是否完成，并调用paser 
    total_length = 0xffffffff 
    has_range = False
    length_unknown = True 
    if "Content-Length" in header: 
        total_length = int(header["Content-Length"]) 
        length_unknown = False 
    if header.get("Accept-Ranges") == "bytes":
        has_range = True
    if header.get("Content-Range"):
        length_unknown = False 
    if task["recv"].tell() >= total_length: 
        parse_http_buffer(task) 
        return 
    if header.get("Transfer-Encoding") == "chunked": 
        if not "chunked_b" in task:
            task["chunked_b"] = StringIO()
            task["chunked_idx"] = 0
        decode_chunk_stream(task) 



STATUS_CONNECT = 0x1 << 3 
STATUS_CONNECTED = 0x1 << 4 
STATUS_SSL_HANDSHAKE = 0x1 << 5
STATUS_FAILED = 0x1 << 6
STATUS_SEND = 0x1 << 7
STATUS_RECV = 0x1 << 8
STATUS_HEADER = 0x1 << 9  
STATUS_DONE = 0x1 << 10



def remove_task(task, why=None): 
    try:
        catch_bug(task, why=why)
    except:
        traceback.print_exc() 



def catch_bug(task, why=None): 
    random = task["random"] 
    if why and config["retry"]: 
        task["reason"] = why
        failed_tasks[random] = task 
    con = task["con"]
    fd = task["fd"] 
    if fd in fd_task: 
        del fd_task[fd] 
    try:
        ep.unregister(fd) 
    except IOError as e:
        pass 
    try:
        con.shutdown(socket.SHUT_RDWR)
    except socket.error:
        pass
    try:
        con.close()
    except OSError:
        pass 
    if random in tasks:
        del tasks[random] 
    task["send"].close() 
    task["recv"].close() 





def connect(task, remote): 
    #开启异步连接
    try:
        reqsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reqsock.setblocking(0)
        reqfd = reqsock.fileno()
        ep.register(reqfd, EPOLLIN|EPOLLOUT|EPOLLERR)
    except Exception as e: 
        if e.errno != errno.EMFILE: 
            remove_task(task, why="create socket: %s" % e)
        return 
    #fd -> task
    fd_task[reqfd] = task
    task["con"] =  reqsock
    task["fd"] = reqfd 
    #有dns缓存则使用
    remote_str = "%s:%s" % remote
    if remote_str in dns_buffer:
        remote = dns_buffer[remote_str] 
    try:
        reqsock.connect(remote)
    except socket.error as e: 
        if e.errno == errno.EINPROGRESS: 
            return
        raise e



def connect_remote(task): 
    #生成请求，暂时写到发送缓冲 
    try:
        remote, content = generate_request(task) 
    except KeyError as e:
        log_with_time("generate_request error: %s" % e)
        return 
    if "remote" in task:
        remote = task["remote"] 
    if task.get("method", METHOD_GET).lower() == "head":
        task["header_only"] = True
    else:
        task["header_only"] = False
    try:
        connect(task, remote)        
    except Exception as e:
        remove_task(task, why="connect remote: %s" % e) 
        return
    task["send"].write(content) 
    task["status"] = STATUS_SEND 
    #设定连接初始化时间 
    task["start"] = time.time()




def send_remain(task):
    #网络阻塞， 重发 
    buf = task["send"]  
    con = task["con"] 
    data = buf.getvalue()
    count = len(data)
    try:
        sent = con.send(data)
    except socket.error as e:
        if e.errno != errno.EAGAIN: 
            remove_task(task, why="write_later send: %s" % e)
        return
    buf.truncate(0)
    #避免busy loop
    if sent != count:
        buf.write(data[sent:])
        ep.modify(task["fd"], EPOLLIN|EPOLLOUT|EPOLLERR)
    else: 
        ep.modify(task["fd"], EPOLLIN|EPOLLERR) 



def send_remain_ssl(task):
    #网络阻塞， 重发 
    buf = task["send"]  
    con = task["ssl_con"] 
    data = buf.getvalue()
    count = len(data) 
    try:
        sent = con.send(data)
    except ssl.SSLError as e: 
        if handle_ssl_exception(task, e) < 0: 
            remove_task(task, why="send_remain_ssl: %s" % e)
            return
    buf.truncate(0)
    #避免busy loop
    if sent != count:
        buf.write(data[sent:])
        ep.modify(task["fd"], EPOLLIN|EPOLLOUT|EPOLLERR)
    else: 
        ep.modify(task["fd"], EPOLLIN|EPOLLERR) 



def read_to_buffer(task): 
    #一次把可用数据读出 
    con = task["con"]
    buf = task["recv"] 
    status = 0
    while True:
        try: 
            mark = buf.tell()
            buf.write(con.recv(409600)) 
            if buf.tell() == mark:
                parse_http_buffer(task) 
                break
        except socket.error as e:
            if e.errno == errno.EAGAIN: 
                status = 1
            else: 
                status = -1
            break
    return status



def handle_read(task): 
    con = task["con"] 
    status = read_to_buffer(task)
    if not status: 
        return
    elif status < 0:
        remove_task(task, why="read_to_buffer error") 
        return
    #找http头并解析 
    if task["status"] & STATUS_RECV:
        parse_header(task)
    if task["status"] & STATUS_HEADER: 
        try:
            parse_response(task["res_header"], task)
        except KeyError as e: 
            remove_task(task, why="解析http响应主体失败: %s" % e)
            return 


def handle_ssl_exception(task, e): 
    status = 1
    errno = e.errno
    #need read
    if errno == ssl.SSL_ERROR_WANT_READ: 
        ep.modify(task["fd"], EPOLLIN | EPOLLERR) 
    #need write
    elif errno == ssl.SSL_ERROR_WANT_WRITE:
        ep.modify(task["fd"], EPOLLIN | EPOLLERR | EPOLLOUT) 
    #other
    else: 
        status = -1
    return status



def read_to_buffer_ssl(task): 
    #一次把可用数据读出 
    con  = task["ssl_con"]
    buf = task["recv"]
    status = 0
    while True:
        try: 
            mark = buf.tell()
            buf.write(con.recv(409600)) 
            if buf.tell() == mark: 
                parse_http_buffer(task)
                break
        except ssl.SSLError as e: 
            if e.errno == ssl.SSL_ERROR_ZERO_RETURN: 
                parse_http_buffer(task) 
            else:
                status = handle_ssl_exception(task, e)
            break
    return status 
                


def handle_read_ssl(task): 
    #ssl handshake packet
    if task["status"] & STATUS_SSL_HANDSHAKE:
        ssl_do_handshake(task) 
        return 
    status = read_to_buffer_ssl(task)
    if not status: 
        return
    elif status < 0:
        remove_task(task, why="read_to_buffer_ssl")
        return 
    #找http头并解析 
    if task["status"] & STATUS_RECV:
        parse_header(task)
    if task["status"] & STATUS_HEADER: 
        try:
            parse_response(task["res_header"], task)
        except KeyError as e: 
            remove_task(task, why="解析http响应主体失败: %s" % e)
            return 



def remote_connected(task): 
    if task.get("ssl"):    
        task["status"] = STATUS_SSL_HANDSHAKE 
        task["ssl_con"] = ssl.wrap_socket(task["con"], do_handshake_on_connect=False)
    else:
        task["status"] = STATUS_RECV 



def ssl_do_handshake(task): 
    con = task["ssl_con"] 
    try:
        con.do_handshake()
        task["status"] = STATUS_RECV 
        ep.modify(task["fd"], EPOLLERR | EPOLLOUT | EPOLLIN)
    except ssl.SSLError as e:
        try:
            handle_ssl_exception(task, e) 
        except ssl.SSLError as e:
            remove_task(task, why="ssl handshake: %s" % e) 



def event_write(task): 
    if task["status"] & STATUS_SEND: 
        remote_connected(task) 
    if task["status"] & STATUS_SSL_HANDSHAKE:
        ssl_do_handshake(task)
        return 
    if task["send"].tell():
        if task.get("ssl"): 
            send_remain_ssl(task) 
        else: 
            send_remain(task) 




def event_read(task): 
    if task.get("ssl"): 
        handle_read_ssl(task) 
    else: 
        handle_read(task) 


def handle_event(ep): 
    time_now = time.time() 
    for fd, event in ep.poll(2): 
        if fd == g["timerfd"]: 
            do_timer()
            continue 
        task = fd_task.get(fd)
        if not task: 
            continue
        if event & EPOLLERR: 
            remove_task(task, why="epoll err") 
            continue 
        if event & EPOLLOUT: 
            task["start"] = time_now 
            event_write(task)
        if event & EPOLLIN:
            task["start"] = time_now
            event_read(task)



def run_debug(): 
    print "======================"
    print "tasks", len(tasks) 
    print "failed", len(failed_tasks)
    print "======================"



def bisect_left(array, item, less): 
    l = 0
    hi = len(array) 
    while l < hi:  
        m = l + (hi - l) / 2
        v = array[m]
        if less(v, item) > 0:
            l = m + 1
        else:
            hi = m - 1
    return l 



def find_new_task(item, zero):
    if item[1]["start"] == 0:
        return -1
    else:
        return 1



def find_timeout(item, cur):
    start = item[1]["start"] 
    if start == 0:
        return 0
    return cur - start - config["timeout"]



def clean_tasks(now): 
    sorted_tasks = sorted(tasks.items(),
            key = lambda x: x[1]["start"],
            reverse=True) 
    mark = bisect_left(sorted_tasks, 
            now,
            find_timeout) 
    for i in range(mark):                
        task = sorted_tasks[i][1] 
        remove_task(task, why="连接超时被清理")



def connect_more(now): 
    sorted_tasks = sorted(tasks.items(),
            key = lambda x: x[1]["start"],
            reverse=True) 
    mark = bisect_left(sorted_tasks,
            0, 
            find_new_task) 
    space = config["limit"] - len(fd_task)
    for _,v in sorted_tasks[mark:]: 
        if space <= 0:
            break 
        if v["con"]:
            continue 
        connect_remote(v) 
        space -= 1 


def do_timer(): 
    assert os.read(g["timerfd"], 8)
    current = time.time() 
    g["timer_signal"] = False
    if current - http_time > config["timeout"]: 
        clean_tasks(current)
        g["http_time"]  = current
    if current - task_time > config["interval"]: 
        connect_more(current)
        g["task_time"] = current



def run_async(ep): 
    g["http_time"] = time.time()
    g["task_time"] = time.time()
    g["timer_signal"] = False 
    while True: 
        try:
            handle_event(ep) 
        except IOError:
            pass 
        #队列完成
        if not len(tasks):
            break 


def fill_task(task): 
    if task.get("chain") and not task.get("chain_idx"): 
        task["chain_idx"] = 0 
        flt = chain_next(task)
        prev = task
        task = flt(prev)
        assert id(task) != id(prev)
        task["prev"] = prev 
    task["send"] = StringIO() 
    task["recv"] = StringIO() 
    copy = {
        "proxy": "", 
        "url": "", 
        "random": "",
        "fd": -1, 
        "parser": nope_parser, 
        "start": 0,
        "retry": 0,
        "status": STATUS_SEND,
        "redirect": 0,
        "con": None,
        "chain": None,
        "chain_idx": 0,
        "ssl": False,
        } 
    for k,v in copy.items():
        if k not in task:
            task[k] = v
    if task["redirect"] and "urlsset" not in task:
        task["urlsset"] = {task["url"]: 1} 
    if task.get("chain") and not task.get("chain_idx"):
        task["chain_idx"] = 1
    return task


def preset_dns(task_list): 
    for i in task_list:
        d = urlparse(i["url"])
        if "host" not in d:
            continue
        host = d["host"]
        if "port" not in d:
            port = 80
        else:
            port = d["port"]
        remote = "%s:%d" % (d["host"], port) 
        if remote in dns_buffer:
            continue
        start = time.time() 
        addrs = socket.getaddrinfo(host, port)
        cost = time.time() - start
        if cost > 1:
            print "dns slow query: %s, %s" % (cost, host)
        if not len(addrs):
            raise socket.error("dns query failed: %s" % host) 
        dns_buffer[remote] = addrs[0][-1] 



def log_with_time(msg):
    print "async_http %s: %s" % (time.ctime(), repr(msg)) 



def dispatch_tasks(task_list): 
    g["ep"] = epoll() 
    #补全任务缺少的
    for i,v in enumerate(task_list): 
        task_list[i] = fill_task(v) 
    #初始化任务管理 
    preset_dns(task_list)
    space = config["limit"]
    start_time = time.time()
    acnt =  len(task_list)
    for i in task_list: 
        while True:
            random = get_random() 
            if not random in tasks:
                tasks[random] = i 
                break
        i["random"] = random 
        if space > 0: 
            connect_remote(i) 
            space -= 1 
    g["timerfd"] = open_timerfd() 
    ep.register(timerfd, EPOLLIN|EPOLLERR)
    run_async(ep) 
    os.close(timerfd) 
    ep.close()
    del g["timerfd"] 
    del g["ep"]
    fcnt = len(failed_tasks) 
    log_with_time("acnt: %d, fcnt: %d, time: %d" % (acnt,
        fcnt, time.time() - start_time))
    for k,v in failed_tasks.iteritems():
        log_with_time("failed: %s" % v["url"])



def repeat_tasks(task_list):
    global failed_tasks
    dispatch_tasks(task_list) 
    while len(failed_tasks):
        ret = [] 
        items = failed_tasks.items()
        failed_tasks = {}
        for key,v in items: 
            if v["retry"] > config["retry_limit"]: 
                continue
            v["retry"] += 1 
            t = default_copy(v) 
            ret.append(t)
        dispatch_tasks(ret) 



def batch_request(urls, parser):
    tasks = []
    for i in urls:
        tasks.append({
            "url": i,
            "parser": parser,
            })
    repeat_tasks(tasks) 



def insert_task(task):
    task = default_copy(task) 
    task = fill_task(task) 
    while True:
        random = get_random()
        if random not in tasks: 
            tasks[random] = task
            break
    task["random"] = random 


def debug_parser(task):
    pprint.pprint(task["res_header"]) 


def sigusr1(signum, frame):
    pdb.set_trace() 


import signal
signal.signal(signal.SIGUSR1, sigusr1) 


def chain_next(task):
    chain = task["chain"]
    idx = task["chain_idx"]
    if idx < len(chain): 
        task["chain_idx"] += 1
        return chain[idx] 



class TIMESPEC(ctypes.Structure):
    """ 
    struct timespec {
        time_t tv_sec;                /* Seconds */
        long   tv_nsec;               /* Nanoseconds */
    };
 
    struct itimerspec {
        struct timespec it_interval;  /* Interval for periodic timer */
        struct timespec it_value;     /* Initial expiration */
    }; 
    """
    _fields_ = [("interval_sec", ctypes.c_long),
                ("interval_nsec", ctypes.c_long),
                ("expire_sec", ctypes.c_long),
                ("expire_nsec", ctypes.c_long),
                ] 



def open_timerfd():
    """ 
    int timerfd_create(int clockid, int flags);

    int timerfd_settime(int fd, int flags,
                       const struct itimerspec *new_value,
                       struct itimerspec *old_value);
    """ 
    libc = ctypes.cdll.LoadLibrary("libc.so.6")
    TFD_NONBLOCK = 00004000
    TFD_CLOEXEC = 02000000 
    CLOCK_MONOTONIC = 1
    fd = libc.timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)
    assert fd != -1
    ts = TIMESPEC(1, 0, 1, 0) 
    assert libc.timerfd_settime(fd, 0, ctypes.pointer(ts), 0) != -1 
    return fd 

