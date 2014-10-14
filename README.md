##一个简单好用的HTTP库, 支持标准的http方法
```shell
In [4]: header, content = simple_http.get("https://github.com")
In [5]: header
Out[5]: 
{'Cache-Control': 'max-age=0, private, must-revalidate',
 'Content-Security-Policy': "default-src *; script-src assets-cdn.github.com www.google-analytics.com collector-cdn.github.com; object-src assets-cdn.github.com; style-src 'self' 'unsafe-inline' 'unsafe-eval' assets-cdn.github.com; img-src 'self' data:assets-cdn.github.com identicons.github.com www.google-analytics.com collector.githubapp.com *.githubusercontent.com *.gravatar.com *.wp.com; media-src 'none'; frame-src 'self' render.githubusercontent.com gist.github.com www.youtube.com player.vimeo.com checkout.paypal.com; font-src assets-cdn.github.com; connect-src 'self' ghconduit.com:25035 live.github.com uploads.github.com s3.amazonaws.com",
 'Content-Type': 'text/html; charset=utf-8',
 'Date': 'Fri, 10 Oct 2014 13:46:09 GMT',
 'ETag': '"37f568db7e0c51e3987492f601ac68d2"',
 'Server': 'GitHub.com',
 'Set-Cookie': [{' HttpOnly': True,
   ' path': '/',
   ' secure': True,
   'cookie': '_gh_sess=eyJzZXNzaW9uX2lkIjoiYmFmYzhiN2E4Yjk1YmQ3NmI0Y2UwMmI0NjRhNjU1MDUiLCJfY3NyZl90b2tlbiI6Ijl2TGNCUWdlODJIVS82UmFHSmp6ZlU2QUFETlFFalRnSTg0QUVnNUtWbms9In0%3D--19d5df32ed9b1662fc7526b563405c96204952bc'}],
 'Status': '200 OK',
 'Strict-Transport-Security': 'max-age=31536000; includeSubdomains; preload',
 'Transfer-Encoding': 'chunked',
 'Vary': 'Accept-Encoding',
 'X-Content-Type-Options': 'nosniff',
 'X-Frame-Options': 'deny',
 'X-GitHub-Request-Id': 'DF418D9C:2C54:CC51D3:5437E321',
 'X-Runtime': '0.008287',
 'X-Served-By': 'b26767d88b31b8e1e88f61422786ec5e',
 'X-UA-Compatible': 'IE=Edge,chrome=1',
 'X-XSS-Protection': '1; mode=block',
 'message': 'OK',
 'protocol': 'HTTP/1.1',
 'status': 200} 

In [6]: pprint.pprint(content[:1024])
'<!DOCTYPE html>\n<html>\n  <head prefix="og: http://ogp.me/ns# fb: http://ogp.me/ns/fb# githubog: http://ogp.me/ns/fb/githubog#">\n    <meta charset=\'utf-8\'>\n    <meta http-equiv="X-UA-Compatible" content="IE=edge">\n        <title>GitHub \xc2\xb7 Build software better, together.</title>\n    <link rel="search" type="application/opensearchdescription+xml" href="/opensearch.xml" title="GitHub" />\n    <link rel="fluid-icon" href="https://github.com/fluidicon.png" title="GitHub" />\n    <link rel="apple-touch-icon" sizes="57x57" href="/apple-touch-icon-114.png" />\n    <link rel="apple-touch-icon" sizes="114x114" href="/apple-touch-icon-114.png" />\n    <link rel="apple-touch-icon" sizes="72x72" href="/apple-touch-icon-144.png" />\n    <link rel="apple-touch-icon" sizes="144x144" href="/apple-touch-icon-144.png" />\n    <link rel="logo" type="image/svg" href="https://github-media-downloads.s3.amazonaws.com/github-logo.svg" />\n    <meta property="og:image" content="https://github.global.ssl.fastly.net/images/modules/logos_page/O'
``` 
###返回头部 
header["status"] 是状态码   
header["message"] 是message   
header["protocol"] 是协议   
它们跟其它头混到在一个字典里, 因为没有区分的必要   

###使用不同的header
默认情况下simple_http使用firefox的User-Agent, 修改示例
```shell
myheader = {
	"Accept": ...
}
simple_http.get("https://google.com", header=myheader) 
```
###使用Cookie
```shell
cookie = {
	"name": "value"
}
simple_http.get("https://github.com", cookie=cookie)
```
###从header里取Cookie用
```shell
simple_http.client_cookie(header["Set-Cookie"])
从
{' path': '/', ' secure': True, 'cookie': '_gh_sess=eyJzZXNzaW9uX2lkIjoiYTU5YTVhMmNjMTE1M2Y2ODU5MDczNjlmNGMzYWVmY2YiLCJfY3NyZl90b2tlbiI6IlVRUy8wdjkycnFhL2R0SGk1NVlkaDQ4d0lnSmljUEYwQzNOSWlGaG50bjQ9In0%3D--177119b094b3292c35f1573c8bd18a41fe8807ef', ' HttpOnly': True}
转换到
{
	"_gh_sess": "...."
}
```
###GET请求添加参数
```shell
query = {
	"params": "value"
}
simple_http.get("https://google.com", query=query) 
```
###POST添加参数
```shell
payload = {
	"params": "value"
}
simple_http.post("https://google.com", payload=payload) 
``` 
###POST里使用文件
```shell
payload = {
	"name": open("test", "r")
}
simple_http.post("https://google.com", payload=payload)
``` 

###使用代理 HTTP and SOCKS5
####Socks5
```shell 
In [8]: simple_http.get("https://google.com", proxy='socks5://127.0.0.1:8888')
Out[8]: 
({'Alternate-Protocol': '443:quic',
  'Cache-Control': 'public, max-age=2592000',
  'Content-Length': '220',
  'Content-Type': 'text/html; charset=UTF-8',
  'Date': 'Wed, 08 Jan 2014 13:28:59 GMT',
  'Expires': 'Fri, 07 Feb 2014 13:28:59 GMT',
  'Location': 'https://www.google.com/',
  'Server': 'gws',
  'X-Frame-Options': 'SAMEORIGIN',
  'X-XSS-Protection': '1; mode=block',
  'message': 'Moved Permanently',
  'protocol': 'HTTP/1.1',
  'status': 301},
 None,
 '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="https://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
```
####http代理
```shell 
In [46]: simple_http.get("https://google.com", proxy='http://127.0.0.1:8088')
Out[46]: 
({'Alternate-Protocol': '443:quic',
  'Cache-Control': 'public, max-age=2592000',
  'Content-Encoding': 'deflate',
  'Content-Length': '172',
  'Content-Type': 'text/html; charset=UTF-8',
  'Date': 'Wed, 08 Jan 2014 13:46:57 GMT',
  'Expires': 'Fri, 07 Feb 2014 13:46:57 GMT',
  'Location': 'https://www.google.com/',
  'Server': 'gws',
  'Via': 'HTTP/1.1 GWA',
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Xss-Protection': '1; mode=block',
  'message': '',
  'protocol': 'HTTP/1.1',
  'status': 301},
 None,
 '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="https://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
``` 
###pretty.py是格式化HTML的工具, 它并不处理js与css, 主要为了澄清文档结构
```shell
python pretty.py input.html > ouput.html
``` 
##etree_utils.py是用于快速确定xpath的工具
因为浏览器会动态修改DOM，从源代码界面取得xpath经常不能用.    
常见的Beautifulsoup效率非常低, 又经常有些奇怪的bug, lxml配合xpath才是抓取网页内容的最佳方案   
主要是辅助快速确定目标的xpath, 使用语法是  
1. a 指tag选择器  
2. .ele 是类选择器  
3. #id 是ID选择器  
4. href="link", =号是属性选择器  
5. >是行选择器   
###示例
```shell
python etree_util.py htmlfile 语法

tag: a
, line: 379
, attrib: {'href': '/album/120712490', 'title': u'\xe8\x9d\xb6\xe6\x81\x8b\xe8\x8a\xb1'}
, text: 目标
, xpath: /html/body/div/ul/li[25]/div/span[6]/a
===============
tag: a
, line: 385
, attrib: {'href': 'javascript:;', 'class': 'btn btn-b play-selected-hook'}
, text: 
        
, xpath: /html/body/div/div[2]/a[1]
===============
tag: a
, line: 394
, attrib: {'href': 'javascript:;', 'class': 'btn btn-b add-selected-hook'}
, text: 
        
, xpath: /html/body/div/div[2]/a[2]
===============
tag: a
, line: 403
, attrib: {'href': 'javascript:;', 'class': 'btn btn-b collect-selected-hook'}
, text: 
        
, xpath: /html/body/div/div[2]/a[3]
===============
tag: a
, line: 412
, attrib: {'href': 'javascript:;', 'class': 'btn btn-b down-selected-hook'}
, text: 
        
, xpath: /html/body/div/div[2]/a[4]

``` 


##encryped_client/server是SOCKS5转发代理 
1. 通过python simple_table.py得到key
2. 要使用先自己修改代码里的端口与服务器地址等配置信息
3. 两者都采用异步非阻塞的高效实现, 在本机测试时cpu从来没有过1%.
4. 加密机制是随机密码表, 转换效率非常高
5. encrypted_server.py与key放到墙外, encrypted_client.py与key放到本地 

##http流解析
主要是为了测试客户端与服务端, 将网络流DUMP到文件，再解析
```shell
python http_stream_parser.py stream.file
```

##http模拟器, 多进程并发模拟浏览器操作
```shell 
$python http_request_simulator.py "weibo.com"
=========
page done: weibo.com
timeout: 3s
=========
url done: http://tp4.sinaimg.cn/1693146987/50/0/0
url done: http://tp4.sinaimg.cn/2669568935/50/0/0
url done: http://tp1.sinaimg.cn/1724196104/50/0/0
url done: http://tp4.sinaimg.cn/1774814087/50/0/0
url done: http://tp4.sinaimg.cn/1736031115/50/0/0
url done: http://tp3.sinaimg.cn/1707759510/50/0/0
url done: http://tp4.sinaimg.cn/2642032423/50/0/0
url done: http://tp4.sinaimg.cn/1730725935/50/0/0
url done: http://tp4.sinaimg.cn/1242716987/50/0/0
url done: http://tp4.sinaimg.cn/1488834727/50/0/0
url done: http://tp3.sinaimg.cn/1871599514/50/0/0
url done: http://tp4.sinaimg.cn/1727873155/50/0/0
url done: http://tp1.sinaimg.cn/1886832164/50/0/0
url done: http://tp1.sinaimg.cn/1589797232/50/0/0
url done: http://tp1.sinaimg.cn/2441302392/50/0/0
url done: http://img.t.sinajs.cn/t35/style/images/tlogin/botlogo.png
url done: http://rs.sinajs.cn/mini.gif?t=w1&uids=1707759510,1759023505,1867565545,1724196104,2669568935,2441302392,1871599514,2642032423,1192428237
url done: http://js.t.sinajs.cn/t35/miniblog/js/yunying_unlogin3.js?version=20131127172405
url done: http://js.t.sinajs.cn/t35/miniblog/js/lang_zh.js?version=20131127172405
url done: http://tp2.sinaimg.cn/1867565545/50/0/0
url done: http://js.t.sinajs.cn/t35/miniblog/static/js/sso.js?v=20131127172405
url done: http://tp2.sinaimg.cn/1192428237/50/0/0
url done: http://i1.sinaimg.cn/unipro/pub/suda_m_v629.js
url done: http://beacon.sina.com.cn/e.gif?noScript
url done: http://tp2.sinaimg.cn/1759023505/50/0/0
request done, kill 0 children
``` 
