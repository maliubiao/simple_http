#-*-encoding=utf-8-*-
import sys
import pdb
#https://github.com/maliubiao/simple_http
import simple_http 
from lxml import etree

xpath = "/html/body/div[3]/div[2]/div[4]/div[2]/ul/li/h6/a"

#锵锵三人行
qqsrx = "http://v.ifeng.com/vlist/tv/qqsrx/all/0/%d/detail.shtml" 
#军事观察室
jqgcs = "http://v.ifeng.com/vlist/tv/jqgcs/all/0/%d/detail.shtml"
#总编辑时间
zbjsj = "http://v.ifeng.com/vlist/tv/zbjsj/all/0/%d/detail.shtml"
#一虎一席谈
yhyxt = "http://v.ifeng.com/vlist/tv/yhyxt/all/0/%d/detail.shtml"
#新闻今日谈
xwjrt = "http://v.ifeng.com/vlist/tv/xwjrt/all/0/%d/detail.shtml"



def do(url, n):
    h, content = simple_http.get(url % n)
    if h["status"] != 200:
        pdb.set_trace()
    s = etree.HTML(content) 
    videos = s.xpath(xpath) 
    for i in videos:
        print "%s\n%s" % (i.attrib["title"],  i.attrib["href"])

if __name__ == "__main__":
    arg1 = sys.argv[1]
    if arg1 == "-q": 
        do(qqsrx, 1)
    elif arg1 == "-j":
        do(jqgcs, 1)
    elif arg1 == "-z":
        do(zbjsj, 1)
    elif arg1 == "-y":
        do(yhyxt, 1)
    elif arg1 == "-x":
        do(xwjrt, 1)
    print "======================="
