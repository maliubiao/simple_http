#-*-encoding=utf-8-*-
#! /usr/bin/env python
from _http import *

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

running = {}

g = globals() 

debug = False


config = {
        "limit": 20, 
        "timeout": 30,
        "interval": 1,
        "retry": True,
        "retry_limit": 3
        } 


failed_tasks = { } 


copy_keys = ("url", "parser", "method")


possible_methods = set(("GET", "POST", "HEAD", "PUT", "DELETE")) 


def default_copy(task):
    t = {}
    for i in copy_keys:
        if i in task:
            t[i] = task[i]
    return t


def generate_request(**kwargs): 
    url = kwargs["url"]
    request_list = []
    urld = urlparse(url) 
    if kwargs.get("query"):
        urld["query"] = generate_query(kwargs["query"]) 
    if "header" in kwargs:
        if not kwargs["header"]:
            header = default_header.copy()
        else:
            header = kwargs["header"]
    else:
        header = default_header.copy() 
    host = urld["host"]
    if "port" in urld:
        port = int(urld["port"])
        header["Host"] = "%s:%d" % (host, port) 
    else:
        port = 80 
        header["Host"] = host
    #没代理
    if not kwargs.get("proxy"): 
        del urld["scheme"] 
        del urld["host"]
        if "port" in urld:
            del urld["port"] 
    else:
        #有代理更新, 连接点换成代理
        pd = urlparse(kwargs["proxy"])
        if pd["scheme"] in "https":
            host = pd["host"]
            port = int(pd["port"])
        else:
            raise Exception("不支持的代理格式") 
    #不处理fragment
    if "fragment" in urld:
        del urld["fragment"] 
    path = generate_url(urld)
    method = kwargs.get("method", METHOD_GET).upper()
    if method not in possible_methods:
        raise ValueError("unsupported method: %s" % method) 
    if method in ("POST", "PUT"):
        content = generate_post(header, kwargs["payload"]) 
        header["Content-Length"] = str(len(content)) 
    request_list.append(generate_client_header(header, method, path))
    if kwargs.get("cookie"):
        request_list.append("Cookie: ")
        request_list.append(generate_cookie(kwargs["cookie"]))
        request_list.append(HEADER_END)
    else:
        request_list.append("\r\n") 
    if method in ("POST", "PUT"): 
        request_list.append(content)
    body = "".join(request_list)
    return (host, port), body 



STATUS_CONNECT = 0x1 << 3
STATUS_CONNECTED = 0x1 << 4 
STATUS_FAILED = 0x1 << 6
STATUS_SEND = 0x1 << 7
STATUS_RECV = 0x1 << 8
STATUS_HEADER = 0x1 << 9  
STATUS_DONE = 0x1 << 10



def pool_set(task, random): 
    host = task["host"] 
    #添加到session 
    if (host in sconf and
            host in session):
        s = session[host]
        #添加到free list, 从busy list中移除
        if len(s["free"]) < sconf[host]: 
            s["free"][random] = task["con"]
            del s["busy"][random]
            return True
    else:
        return False


def remove_task(task, why=None):
    try:
        catch_bug(task, why=why)
    except Exception as e:
        print "async_http: remove_task: %s" % str(e)


def catch_bug(task, why=None): 
    random = task["random"] 
    if why and config["retry"]: 
        task["reason"] = why
        failed_tasks[random] = task 
    con = task["con"]
    fd = task["fd"] 
    #先清理这个
    if fd in fd_task:
        del fd_task[fd] 
    try:
        ep.unregister(fd) 
    except IOError:
        pass 
    if why or not pool_set(task, random):
        try:
            con.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass
        try:
            con.close()
        except OSError:
            pass 
    #关闭缓冲
    task["send"].close() 
    task["recv"].close() 
    #清理注册 
    if random in running:
        del running[random] 
    if random in tasks:
        del tasks[random] 



#连接池
sconf =  {} 
session = {}

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
        if e.errno != errno.EINPROGRESS: 
            remove_task(task, why="connect remote: %s" % e) 
            return 
    return reqsock



def get_sock(task, remote): 
    host = "%s:%d" % remote 
    _, sock = session[host]["free"].popitem() 
    #检测一下socket本地关闭
    try: 
        sock.setblocking(0) 
    except socket.error: 
        sock = connect(task, remote) 
    fd = sock.fileno()
    try:
        ep.register(fd, EPOLLIN|EPOLLOUT|EPOLLERR)
    except:
        remove_task(task, why="epoll注册失败")
        return
    rand = task["random"]
    #fd -> task
    fd_task[fd] = task
    #检测一下socket远程关闭
    try: 
        x = sock.recv(1) 
        sock = connect(task, remote)
    except socket.error as e:
        if e.errno != errno.EAGAIN: 
            sock = connect(task, remote) 
    task["con"] = sock 
    task["fd"] = fd
    #标记为已用
    session[host]["busy"][rand] = sock
    return sock 



def pool_get(task, remote): 
    host = "%s:%d" % remote 
    task["host"] = host 
    #如果配置了连接池
    if host in sconf: 
        #如果池里有项
        if host in session:
            #如果有可用的
            s = session[host]
            if len(s["free"]): 
                sock = get_sock(task, remote) 
            #没有则新建
            else:
                sock = connect(task, remote)
                s["busy"][task["random"]] = sock
        #如果池里没有则新建
        else: 
            sock = connect(task, remote) 
            #用字典管理可用与否的socket
            session[host] = {
                    "busy": {task["random"]: sock},
                    "free": {},
                    }
    #没有配置连接池只用一次
    else:
        sock = connect(task, remote)
    task["con"] = sock


def connect_remote(task): 
    #生成请求，暂时写到发送缓冲 
    try:
        remote, content = generate_request(**task) 
    except KeyError as e:
        log_with_time("generate_request error: %s" % e)
        return 
    if "remote" in task:
        remote = task["remote"] 
    if task.get("method", METHOD_GET).lower() == "head":
        task["header_only"] = True
    else:
        task["header_only"] = False
    pool_get(task, remote) 
    task["send"].write(content) 
    task["status"] = STATUS_SEND 
    #设定连接初始化时间 
    task["start"] = time.time()


def handle_write_later(task):
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



def read_to_buffer(con, buf): 
    #一次把可用数据读出
    while 1:
        try: 
            #内存复制问题
            mark = buf.tell()
            buf.write(con.recv(409600)) 
            #连接终止退出
            if buf.tell() == mark:
                return True
        except socket.error as e:
            if e.errno == errno.EAGAIN:
                return False
            raise e 

            



def call_parser(task): 
    enc =  task["resp_header"].get("Content-Encoding") 
    text = task["recv"].getvalue() 
    task["recv"].truncate(0) 
    task["text"] = text
    if enc == "gzip": 
        task["text"] = zlib.decompress(text, 16+zlib.MAX_WBITS)
    elif enc == "deflate": 
        task["text"] = zlib.decompress(text, -zlib.MAX_WBITS) 
    task["parser"](task) 



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
    task["chunked_idx"] = recv.tell()
    recv.seek(recv_end, io.SEEK_SET)
    if done: 
        task["recv"] = task["chunked_b"] 
        del task["chunked_b"] 
        del task["chunked_idx"]
        call_parser(task) 
        remove_task(task)   

    


def parse_http_buffer(task): 
    header = task.get("resp_header")
    if not header:
        remove_task(task)
        return
    if header.get("Transfer-Encoding") == "chunked":
        decode_chunked(task)
    call_parser(task) 
    remove_task(task)   
    


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



def handle_pollin(task): 
    con = task["con"]
    recv = task["recv"] 
    if read_to_buffer(con, recv): 
        parse_http_buffer(task)
        return
    #找http头并解析 
    if task["status"] & STATUS_RECV:
        content = recv.getvalue()
        body_pos = content.find("\r\n\r\n") 
        #没找到头再等 
        if body_pos < 0:
            return
        task["status"] = STATUS_HEADER
        recv.truncate(0)
        recv.write(content[body_pos+4:]) 
        try:
            task["resp_header"] = parse_server_header(content[:body_pos]) 
        except (ValueError, IndexError, TypeError) as e: 
            remove_task(task, why="解析http头失败: %s" % e)
            return 
        if task["header_only"]:
            call_parser(task)
            remove_task(task)
            return
    if task["status"] & STATUS_HEADER: 
        try:
            parse_response(task["resp_header"], task)
        except ValueError as e: 
            remove_task(task, why="解析http响应主体失败: %s" % e)
            return 



def handle_remote_connect(task): 
    #一次不要发太多请求
    if len(running) > config["limit"]: 
        return 
    #能发送则发送并加计数
    running[task["random"]] = task
    task["status"] = STATUS_RECV 



def handle_event(ep): 
    for fd, event in ep.poll(2): 
        #不太可能的情况
        if fd not in fd_task: 
            try:
                ep.unregister(fd)
            except:
                pass
            continue
        #可能在任何时候被信号中断
        try:
            task = fd_task[fd] 
        except KeyError:
            continue
        if event & EPOLLERR:
            #出错，清理任务 
            remove_task(task, why="epoll err") 
            continue
        if event & EPOLLOUT: 
            if task["status"] & STATUS_SEND:
                task["start"] = time.time() 
                handle_remote_connect(task) 
            if task["send"].tell():
                #连接有有效活动更新活动时间 
                task["start"] = time.time() 
                try:
                    handle_write_later(task) 
                except ValueError:  
                    remove_task(task, why="write later时buffer失效")
                    continue
        if event & EPOLLIN:
            #连接有有效活动更新活动时间 
            task["start"] = time.time()
            try:
                handle_pollin(task) 
            except ValueError:
                remove_task(task, why="处理pollin时buffer失效")


def run_debug(): 
    print "======================"
    print "tasks", len(tasks)
    print "running", len(running)
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



def do_timer(): 
    current = time.time() 
    g["timer_signal"] = False
    if current - http_time > config["timeout"]: 
        #根据任务开始的时间排序
        sorted_tasks = sorted(tasks.items(),
                key = lambda x: x[1]["start"],
                reverse=True) 
        #二分查找超时任务 
        mark = bisect_left(sorted_tasks, 
                current,
                find_timeout) 
        for i in range(mark):                
            task = sorted_tasks[i][1] 
            remove_task(task, why="连接超时被清理")
        g["http_time"]  = current
    if current - task_time > config["interval"]: 
        #二分查找启用新任务
        #根据任务开始的时间排序
        sorted_tasks = sorted(tasks.items(),
                key = lambda x: x[1]["start"],
                reverse=True) 
        mark = bisect_left(sorted_tasks,
                0, 
                find_new_task) 
        space = config["limit"] - len(running)
        for _,v in sorted_tasks[mark:]: 
            if space <= 0:
                break
            #如果有空位则发布新的任务
            if not v["con"]:
                try:
                    connect_remote(v) 
                except ValueError as e:
                    remove_task(v, why="连接时buffer失效")
                    continue 
                space -= 1 
        g["task_time"] = current 


def run_async(ep): 
    g["http_time"] = time.time()
    g["task_time"] = time.time()
    g["timer_signal"] = False
    signal.setitimer(signal.ITIMER_REAL, 1, 1)
    signal.signal(signal.SIGALRM, internal_timer)
    while True: 
        try:
            handle_event(ep) 
        except IOError:
            pass
        except ValueError:
            pass
        if timer_signal:
            do_timer()
        #队列完成
        if not len(tasks):
            break 
    #关闭时间信号
    signal.setitimer(signal.ITIMER_REAL, 0, 0) 


def internal_timer(signum, frame): 
    if debug:
        run_debug() 
    g["timer_signal"] = True



def fill_task(task): 
    task["send"] = StringIO() 
    task["recv"] = StringIO() 
    copy = {
        "proxy": "",
        "cookie": "", 
        "url": "",
        "header": {}, 
        "random": "",
        "fd": -1, 
        "resp_header": {},
        "parser": nope_parser, 
        "start": 0,
        "retry": 0,
        "status": STATUS_SEND,
        "con": None,
        } 
    for k,v in copy.items():
        if k not in task:
            task[k] = v


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
    print u"async_http %s: %s" % (time.ctime(), repr(msg)) 



def dispatch_tasks(task_list): 
    g["ep"] = epoll() 
    #补全任务缺少的
    for i in task_list: 
        fill_task(i) 
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
            try:
                connect_remote(i)
            except ValueError as e: 
                remove_task(i, why="连接时buffer失效")
                continue
            space -= 1 
    run_async(ep) 
    fcnt = len(failed_tasks) 
    log_with_time("acnt: %d, fcnt: %d, time: %d" % (acnt,
        fcnt, time.time() - start_time))
    for k,v in failed_tasks.iteritems():
        log_with_time("failed: %s" % v["url"])



def loop_until_done(task_list):
    global failed_tasks
    dispatch_tasks(task_list) 
    while len(failed_tasks):
        ret = [] 
        items = failed_tasks.items()
        failed_tasks = {}
        for key,v in items: 
            if v["retry"] > config["retry_limit"]:
                del failed_tasks[key]
                continue
            t = default_copy(v)
            v["retry"] += 1
            ret.append(t)
        dispatch_tasks(ret) 



def insert_task(task):
    task = default_copy(task)
    fill_task(task)
    while True:
        random = get_random()
        if random not in tasks: 
            tasks[random] = task
            break
    task["random"] = random 



def wait_timeout(n): 
    #临时忽略itimer产生的信号
    signal.signal(signal.SIGALRM, signal.SIG_IGN)
    time.sleep(n) 
    #恢复信号处理
    signal.signal(signal.SIGALRM, internal_timer)



def debug_parser(task):
    pprint.pprint(task["resp_header"]) 




def sigusr1(signum, frame):
    pdb.set_trace()



import signal
signal.signal(signal.SIGUSR1, sigusr1) 
