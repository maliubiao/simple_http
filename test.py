import simple_http
import socket
import signal
import os
import pdb
import pprint
from uuid import uuid4

get_expect = hash('GET /?t2=v2&t1=v1 HTTP/1.1\r\nAccept-Language: zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nHost: 127.0.0.1:6711\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/32.0\r\nConnection: keep-alive\r\n\r\n')

post_simple_expect = hash('POST / HTTP/1.1\r\nContent-Length: 11\r\nAccept-Language: zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nHost: 127.0.0.1:6711\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/32.0\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nt2=v2&t1=v1')

post_complex_expect = hash('POST / HTTP/1.1\r\nContent-Length: 185\r\nAccept-Language: zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nHost: 127.0.0.1:6711\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/32.0\r\nConnection: keep-alive\r\nContent-Type: multipart/form-data; boundary=5179bb8b89f840a685ea0f09dd589f43\r\n\r\n--5179bb8b89f840a685ea0f09dd589f43\r\nContent-Disposition: form-data; name="t1"; filename="test.txt"\r\nContent-Type: application/octet-stream\r\n\r\ntest\n\r\n--5179bb8b89f840a685ea0f09dd589f43--')

config = {
        "get": get_expect,
        "post_simple": post_simple_expect,
        "post_complex": post_complex_expect
        }

simple_http.set_boundary("5179bb8b89f840a685ea0f09dd589f43") 

def run_http(tp):
    if not os.fork():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 6711))
        sock.listen(1) 
        os.kill(os.getppid(), signal.SIGINT) 
        con, addr = sock.accept()
        result = con.recv(4096) 
        pprint.pprint(result)
        h = hash(result)
        if tp == "get":
            if h == config[tp]:
                print "get pass"
            else:
                print "get failed" 
        elif tp == "post_simple":
            if h == config[tp]:
                print "post simple pass"
            else:
                print "post simple failed" 
        elif tp == "post_complex":
            if h == config[tp]:
                print "post complex pass"
            else:
                print "post complex failed"
        exit(0)


def run_http_proxy():
    if not os.fork():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.socksetopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 6711))
        sock.listen(1) 
        os.kill(os.getppid(), signal.SIGUSR1) 
        result = sock.recv(4096) 


def run_socks5_proxy(): 
    if not os.fork():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.socksetopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 6711))
        sock.listen(1) 
        os.kill(os.getppid(), signal.SIGUSR1) 
        result = sock.recv(4096) 


def task_get(): 
    run_http("get") 
    try:
        os.wait()
    except KeyboardInterrupt:
        pass 
    payload = {
            "t1": "v1",
            "t2": "v2"
            } 
    simple_http.get("127.0.0.1:6711", query = payload)
    pdb.set_trace()



def task_get_http(): 
    run_http("get_http") 
    try:
        os.wait()
    except KeyboardInterrupt:
        pass 
    payload = {
            "t1": "v1",
            "t2": "v2"
            } 
    simple_http.get("127.0.0.1:6711", query = payload)
    pdb.set_trace()


def task_get_socks5(): 
    run_http("get_socks5") 
    try:
        os.wait()
    except KeyboardInterrupt:
        pass 
    payload = {
            "t1": "v1",
            "t2": "v2"
            } 
    simple_http.get("127.0.0.1:6711", query = payload) 
    pdb.set_trace()


def task_post_simple(): 
    run_http("post_simple") 
    try:
        os.wait()
    except KeyboardInterrupt:
        pass 
    payload = {
            "t1": "v1",
            "t2": "v2"
            }
    h, c = simple_http.post("127.0.0.1:6711", payload = payload) 
    pdb.set_trace()

def task_post_complex(): 
    run_http("post_complex") 
    try:
        os.wait()
    except KeyboardInterrupt:
        pass 
    payload = {
            "t1": "v1",
            "t1": open("test.txt", "r")
            } 
    h, c = simple_http.post("127.0.0.1:6711", payload = payload) 

