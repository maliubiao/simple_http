## 简单易用的同步/异步http库
### 安装
```shell
sudo python setup.py install
```

### 异步方式
```shell 

In [21]: def print_it(x):                                                              
    import pprint
   ....:     pprint.pprint(x)
   ....:     

In [22]: async_http.repeat_tasks([{"url": "http://www.baidu.com", "parser": print_it}])
{'chain': None,
 'chain_idx': 0,
 'con': <socket._socketobject object at 0x2812bb0>,
 'fd': 5,
 'header_only': False,
 'parser': <function print_it at 0x283da28>,
 'proxy': '',
 'random': '60804c2a0b053fbd',
 'recv': <cStringIO.StringO object at 0x283a3e8>,
 'redirect': 0,
 'res_cookie': {'BAIDUID': {'domain': '.baidu.com',
                            'expires': 'Thu, 31-Dec-37 23:55:55 GMT',
                            'max-age': '2147483647',
                            'path': '/',
                            'value': 'BCB0BBBB4312D00C88BCDC9EEAAE3726:FG=1'},
                'BD_LAST_QID': {'Max-Age': '1',
                                'path': '/',
                                'value': '16069052107084303783'},
                'BIDUPSID': {'domain': '.baidu.com',
                             'expires': 'Thu, 31-Dec-37 23:55:55 GMT',
                             'max-age': '2147483647',
                             'path': '/',
                             'value': 'BCB0BBBB4312D00C88BCDC9EEAAE3726'}},
 'res_header': {'Connection': 'Keep-Alive',
                'Content-Length': '215',
                'Content-Type': 'text/html',
                'Date': 'Thu, 21 May 2015 15:50:43 GMT',
                'Location': 'https://www.baidu.com/',
                'P3P': 'CP=" OTI DSP COR IVA OUR IND COM "',
                'Server': 'BWS/1.1',
                'Set-Cookie': 'BAIDUID=BCB0BBBB4312D00C88BCDC9EEAAE3726:FG=1; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com\r\nBIDUPSID=BCB0BBBB4312D00C88BCDC9EEAAE3726; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com\r\nBD_LAST_QID=16069052107084303783; path=/; Max-Age=1',
                'X-UA-Compatible': 'IE=Edge,chrome=1'},
 'res_status': {'message': 'Moved Temporarily',
                'protocol': 'HTTP/1.1',
                'status': 302},
 'retry': 0,
 'send': <cStringIO.StringO object at 0x25fb8f0>,
 'ssl': False,
 'start': 1432223278.489937,
 'status': 512,
 'text': '<html>\r\n<head><title>302 Found</title></head>\r\n<body bgcolor="white">\r\n<center><h1>302 Found</h1></center>\r\n<hr><center>pr-nginx_1-0-221_BRANCH Branch\nTime : Wed May 20 10:35:46 CST 2015</center>\r\n</body>\r\n</html>\r\n',
 'url': 'http://www.baidu.com'}
async_http Thu May 21 23:47:58 2015: 'acnt: 1, fcnt: 0, time: 0'
```


### 同步方式

```shell
In [1]: import simple_http

In [2]: res = simple_http.get("https://github.com")

In [4]: res["status"]
Out[4]: 200

In [5]: res["message"]
Out[5]: 'OK'

In [6]: res["protocol"]
Out[6]: 'HTTP/1.1'

In [7]: res["header"]
Out[7]: 
{'Cache-Control': 'no-cache',
 'Content-Security-Policy': "default-src *; script-src assets-cdn.github.com collector-cdn.github.com; object-src assets-cdn.github.com; style-src 'self' 'unsafe-inline' 'unsafe-eval' assets-cdn.github.com; img-src 'self' data:assets-cdn.github.com identicons.github.com www.google-analytics.com collector.githubapp.com *.githubusercontent.com *.gravatar.com *.wp.com; media-src 'none'; frame-src 'self' render.githubusercontent.com gist.github.com www.youtube.com player.vimeo.com checkout.paypal.com; font-src assets-cdn.github.com; connect-src 'self' live.github.com wss://live.github.com uploads.github.com status.github.com api.github.com www.google-analytics.com github-cloud.s3.amazonaws.com",
 'Content-Type': 'text/html; charset=utf-8',
 'Date': 'Thu, 21 May 2015 15:38:29 GMT',
 'Server': 'GitHub.com',
 'Set-Cookie': 'logged_in=no; domain=.github.com; path=/; expires=Mon, 21 May 2035 15:38:29 -0000; secure; HttpOnly\r\n_gh_sess=eyJzZXNzaW9uX2lkIjoiNzk3MWNkZDEzZDJhOTA2NzZjYTEzYjExZDYxN2VhMjMiLCJfY3NyZl90b2tlbiI6IjZ0OENRUllFWjQ4NVlud2VGaC96aGVRbTBsZSs2K1FCVTJxcTdNSjlIM0E9In0%3D--1a2444a9b86de98df0ea2556dbc5644b239aa7b0; path=/; secure; HttpOnly',
 'Status': '200 OK',
 'Strict-Transport-Security': 'max-age=31536000; includeSubdomains; preload',
 'Transfer-Encoding': 'chunked',
 'Vary': 'Accept-Encoding',
 'X-Content-Type-Options': 'nosniff',
 'X-Frame-Options': 'deny',
 'X-GitHub-Request-Id': '774ED627:7040:139FB8B:555DFBF4',
 'X-Request-Id': 'c23d860f8a94048323f1185a15176c13',
 'X-Runtime': '0.007538',
 'X-Served-By': '63914e33d55e1647962cf498030a7c16',
 'X-UA-Compatible': 'IE=Edge,chrome=1',
 'X-XSS-Protection': '1; mode=block'

In [8]: res["text"][:100]
Out[8]: '<!DOCTYPE html>\n<html lang="en" class="">\n  <head prefix="og: http://ogp.me/ns# fb: http://ogp.me/ns'
``` 
### 自动重定向
```shell
In [9]: simple_http.get("http://baidu.com")
redirect to https://www.baidu.com/
Out[9]: 
{'cookie': {},
 'header': {'Cache-Control': 'private',
  'Connection': 'Keep-Alive',
  'Content-Length': '160',
  'Content-Type': 'text/html',
  'Date': 'Thu, 21 May 2015 15:44:46 GMT',
  'Expires': 'Fri, 22 May 2015 15:44:46 GMT',
  'Location': 'https://www.baidu.com/',
  'Server': 'bfe/1.0.8.2'},
 'message': 'Moved Temporarily',
 'protocol': 'HTTP/1.1',
 'status': 302,
 'text': '<html>\r\n<head><title>302 Found</title></head>\r\n<body bgcolor="white">\r\n<center><h1>302 Found</h1></center>\r\n<hr><center>bfe/1.0.8.2</center>\r\n</body>\r\n</html>\r\n',
 'total_length': 160,
 'url': 'http://baidu.com'}

In [6]: res = simple_http.get("http://www.baidu.com", redirect=10)
redirect to https://www.baidu.com/

In [7]: res["status"]
Out[7]: 200

In [8]: res["header"]
Out[8]: 
{'BDPAGETYPE': '1',
 'BDQID': '0x857e6d5d0000bf0d',
 'BDUSERID': '0',
 'Cache-Control': 'private',
 'Connection': 'keep-alive',
 'Content-Encoding': 'gzip',
 'Content-Type': 'text/html; charset=utf-8',
 'Cxy_all': 'baidu+f132f05584d0062745fea455fbb7d59f',
 'Date': 'Thu, 21 May 2015 15:54:44 GMT',
 'Expires': 'Thu, 21 May 2015 15:54:44 GMT',
 'Server': 'bfe/1.0.8.2',
 'Set-Cookie': 'BDSVRTM=11; path=/\r\nBD_HOME=0; path=/\r\nH_PS_PSSID=13782_1426_13519_13075_12868_14166_14297_10562_12722_14155_14172_13203_14244_11518_13932_14309_14321_14182_8498_14195; path=/; domain=.baidu.com\r\n__bsi=11945547936248309498_00_34_N_N_17_0303_C02F_N_N_N; expires=Thu, 21-May-15 15:54:49 GMT; domain=www.baidu.com; path=/',
 'Transfer-Encoding': 'chunked',
 'Vary': 'Accept-Encoding',
 'X-Powered-By': 'HPHP',
 'X-UA-Compatible': 'IE=Edge,chrome=1'}
``` 

### 使用不同的header
默认情况下simple_http使用firefox的User-Agent, 
```shell
myheader = {
	"Accept": ...
}
simple_http.get("https://google.com", header=myheader) 
```
### 使用Cookie
```shell
cookie = {
	"name": "value"
}
simple_http.get("https://github.com", cookie=cookie)
```
### 从header里取Cookie用
```shell
simple_http.get_cookie(res["cookie"]) 

```
### GET请求添加参数
```shell
query = {
	"params": "value"
}
simple_http.get("https://google.com", query=query) 
```
### POST添加参数
```shell
payload = {
	"params": "value"
}
simple_http.post("https://google.com", payload=payload) 
``` 
### POST里使用文件
```shell
payload = {
	"name": open("test", "r")
}
simple_http.post("https://google.com", payload=payload)
``` 

### 使用代理
#### Socks5
```shell 
In [3]: simple_http.get("https://google.com", proxy='socks5://127.0.0.1:9988')
redirect to https://www.google.co.jp/?gfe_rd=cr&ei=phuEVfPKEYuT8QfC4YCgBA
Out[3]: 
{'cookie': {},
 'header': {'Alternate-Protocol': '443:quic,p=1',
  'Cache-Control': 'private',
  'Content-Length': '262',
  'Content-Type': 'text/html; charset=UTF-8',
  'Date': 'Fri, 19 Jun 2015 13:39:50 GMT',
  'Location': 'https://www.google.co.jp/?gfe_rd=cr&ei=phuEVfPKEYuT8QfC4YCgBA',
  'Server': 'GFE/2.0'},
 'message': 'Found',
 'protocol': 'HTTP/1.1',
 'status': 302,
 'text': '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>302 Moved</TITLE></HEAD><BODY>\n<H1>302 Moved</H1>\nThe document has moved\n<A HREF="https://www.google.co.jp/?gfe_rd=cr&amp;ei=phuEVfPKEYuT8QfC4YCgBA">here</A>.\r\n</BODY></HTML>\r\n',
 'total_length': 262,
 'url': 'https://google.com'}

```
#### http代理
```shell 
In [3]: simple_http.get("https://google.com", proxy='http://127.0.0.1:9988')
redirect to https://www.google.co.jp/?gfe_rd=cr&ei=phuEVfPKEYuT8QfC4YCgBA
Out[3]: 
{'cookie': {},
 'header': {'Alternate-Protocol': '443:quic,p=1',
  'Cache-Control': 'private',
  'Content-Length': '262',
  'Content-Type': 'text/html; charset=UTF-8',
  'Date': 'Fri, 19 Jun 2015 13:39:50 GMT',
  'Location': 'https://www.google.co.jp/?gfe_rd=cr&ei=phuEVfPKEYuT8QfC4YCgBA',
  'Server': 'GFE/2.0'},
 'message': 'Found',
 'protocol': 'HTTP/1.1',
 'status': 302,
 'text': '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>302 Moved</TITLE></HEAD><BODY>\n<H1>302 Moved</H1>\nThe document has moved\n<A HREF="https://www.google.co.jp/?gfe_rd=cr&amp;ei=phuEVfPKEYuT8QfC4YCgBA">here</A>.\r\n</BODY></HTML>\r\n',
 'total_length': 262,
 'url': 'https://google.com'}
```



