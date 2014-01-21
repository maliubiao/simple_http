import socket
from struct import pack

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 9988))
sock.sendall("\x05\x01\x00")

url = "www.google.com"
socks_url = "\x05\x01\x00\x03%s%s%s" % (pack(">B", len(url)), url, pack(">H", 443)) 

print sock.recv(12).encode("hex")
sock.sendall(socks_url)
print sock.recv(128).encode("hex")

header ="GET / HTTP/1.1\x0d\x0aAccept-Language: zh,zh-cn;q=0.8,en-us;q=0.5,en;q=0.3\x0d\x0aAccept-Encoding: gzip, deflate\x0d\x0aHost: www.ifeng.com:80\x0d\x0aAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\x0d\x0aUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko/20100101 Firefox/25.0\x0d\x0a\x0d\x0a"
sock.sendall(header)

f = open("test3", "w") 

total = 0
while True:
    data = sock.recv(4096) 
    total += len(data)
    print total
    if data:
        f.write(data)
        f.flush()
    else:
        break 
