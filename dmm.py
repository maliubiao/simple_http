#-*-encoding=utf8-*-
import pdb
import simple_http
from lxml import etree
import os.path
import re
import sys

#代理
proxy = None

dvd = "http://www.dmm.co.jp/mono/dvd/-/actress/"

digital_base = "http://www.dmm.co.jp/digital/videoa/-/actress/"

digital = digital_base + "recommend/"

#拼音分类
proun =  "/html/body/table/tr/td[2]/div[1]/table[2]/tr/td/a"
last = "/html/body/table/tr/td[2]/div[1]/div[2]/div[2]/ul/li/a"

#两种演员名
ps_digital = "/html/body/table/tr/td[2]/div/div[3]/ul/li/a" 
p_digital = "/html/body/table/tr/td[2]/div/div[5]/ul/li/a" 

base = "http://www.dmm.co.jp"

p = "/html/body/table/tr/td[2]/div[1]/div[3]/ul/li/a" 

#digital 搜索页
p_work_title = "/html/body/table/tr/td[2]/div[1]/div/div[3]/div/ul/li/div/p[2]/a/span[1]/img" 
p_work_url = "/html/body/table/tr/td[2]/div[1]/div/div[3]/div/ul/li/div/p[2]/a" 
p_work_last = "/html/body/table/tr/td[2]/div[1]/div/div[1]/div[1]/ul/li/a" 

#dvd 搜索页
work_url = "/html/body/table/tr/td[2]/div[1]/div/div[2]/div/ul/li/div/p[2]/a"
#work_title = "/html/body/table/tr/td[2]/div[1]/div/div[2]/div/ul/li/div/p[2]/a/span" 
work_title2 = "/html/body/table/tr/td[2]/div[1]/div/div[2]/div/ul/li/div/p[2]/a/span/img" 
author_name = "/html/body/table/tr/td[2]/div[1]/div/div[2]/div/ul/li/div/p[3]/span" 
work_last = "/html/body/table/tr/td[2]/div[1]/div/div[4]/div[1]/div/ul/li/a"

#信息页
cover = "/html/body/table/tr/td[2]/div[1]/table/tr/td[1]/div[1]/div/div[1]/a[1]" 
photo = "/html/body/table/tr/td[2]/div[1]/table/tr/td[1]/div[6]/a/img" 
title = "/html/body/table/tr/td[2]/div/div[1]/div/h1" 
aid = "/html/body/table/tr/td[2]/div[1]/table/tr/td[1]/table/tr/td[2]"


#小图换大图
bigpic = re.compile('-[0-9]{0,2}\.jpg')

#跳过剪辑的垃圾
skip = u"ベスト・総集編"
skip_xpath = "/html/body/table/tr/td[2]/div/table/tr/td[1]/table/tr[10]/td[2]/a"


def page_to_id(page):
    return int(page.split("=")[-1].strip("/")) 

def utf8(s): 
    return s.encode("utf8")

def replace(pattern, src, sub):
    i  = pattern.findall(src)[0]
    return src.replace(i, sub+i) 

def get_author_list(category): 
    res = simple_http.get(category, proxy=proxy)
    t = etree.HTML(res["text"])
    urls = t.xpath(last)
    total = 0
    if len(urls) == 0:
        total = 0
    elif len(urls) < 6: 
        total = page_to_id(urls[-2].attrib["href"]) 
    else:
        total = page_to_id(urls[-1].attrib["href"]) 
    for i in t.xpath(p): 
        print utf8(i.xpath("string()"))
        print utf8(base+i.attrib["href"])
    for i in range(2, total+1):
        res = simple_http.get(category + "/page=%d" % i, proxy=proxy)
        t = etree.HTML(res["text"])
        for i in t.xpath(p):
            if not i.text:
                continue
            print utf8(i.xpath("string()"))
            print utf8(base+i.attrib["href"])


def get_work_list(author_url):
    if not author_url:
        pdb.set_trace()
    res = simple_http.get(author_url, proxy=proxy) 
    if res["status"] != 200:
        pdb.set_trace()
    t = etree.HTML(res["text"])
    urls = t.xpath(work_last) 
    total = 0
    ret = []
    if len(urls) == 0:
        total = 0
    elif len(urls) < 6: 
        total = page_to_id(urls[-2].attrib["href"]) 
    else:
        total = page_to_id(urls[-1].attrib["href"]) 
    ret.extend(zip([x.attrib["src"] for x in t.xpath(work_title2)],
        [base+x.attrib["href"] for x in t.xpath(work_url)], 
        [x.text for x in t.xpath(author_name)])) 
    for i in range(2, total+1): 
        res = simple_http.get(author_url + "page=%d/" % i, proxy=proxy)
        t = etree.HTML(res["text"])
        ret.extend(zip([x.attrib["src"] for x in t.xpath(work_title2)],
            [base+x.attrib["href"] for x in t.xpath(work_url)], 
            [x.text for x in t.xpath(author_name)])) 
    return ret


def get_info(work_url): 
    res = simple_http.get(work_url, proxy=proxy)
    t = etree.HTML(res["text"])
    tags = t.xpath(skip_xpath)
    for i in tags:
        if i.text == skip:
            return {}
    try: 
        cover_img = t.xpath(cover)[0].attrib["href"]
    except:
        cover_img = ""
    pics = [replace(bigpic, x.attrib["src"], "jp") for x in t.xpath(photo)] 
    try:
        name = t.xpath(title)[0].text
    except:
        name = ""
    try: 
        id = t.xpath(aid)[-2].text 
    except:
        id = ""
    return {
            "cover": cover_img,
            "pics": pics,
            "name": name,
            "aid": id
            }


def get_category_dvd(): 
    res = simple_http.get(dvd, proxy=proxy) 
    t = etree.HTML(res["text"])
    urls = t.xpath(proun)
    for i in urls: 
        print utf8(i.text)
        get_author_list(base+i.attrib["href"]) 
        
#根据五十音生成
def get_categroy_digital(): 
    p1 = ["", "k", "s", "t", "n", "h", "m", "y", "r", "w"]
    p2 = ["a", "i", "u", "e", "o"]
    pages = []
    for i in p1:
        pages.extend(["%s=/keyword=%s/" % (digital_base, i+x) for x in p2]) 
    authors = [] 
    for i in pages:
        res = simple_http.get(i, proxy=proxy)
        t = etree.HTML(res["text"]) 
        for i in t.xpath(p_digital) + t.xpath(ps_digital): 
            if not i.text:
                continue
            print utf8(i.xpath("string()"))
            print utf8(i.attrib.get("href"))



def get_work_list_digital(author_url): 
    res = simple_http.get(author_url, proxy=proxy, redirect=10) 
    t = etree.HTML(res["text"]) 
    urls = t.xpath(p_work_last) 
    total = 0
    ret = []
    if len(urls) == 0:
        total = 0
    elif len(urls) < 6: 
        total = page_to_id(urls[-2].attrib["href"]) 
    else:
        total = page_to_id(urls[-1].attrib["href"]) 
    ret.extend(zip([x.attrib["alt"] for x in t.xpath(p_work_title)],
        [x.attrib["href"] for x in t.xpath(p_work_url)])) 
    for i in range(2, total+1): 
        res = simple_http.get(author_url + "page=%d/" % i, proxy=proxy) 
        t = etree.HTML(res["text"])
        ret.extend(zip([x.attrib["alt"] for x in t.xpath(p_work_title)],
            [x.attrib["href"] for x in t.xpath(p_work_url)])) 
    return ret 


def down_list_digital(author_url): 
    work_list = get_work_list_digital(author_url) 
    for alias, work_url in work_list: 
        d = get_info(work_url) 
        if not d:
            continue
        name = d["name"]
        if not name:
            name = alias
        if d["cover"]:
            down_pic("%s-%s-cover.jpg" % (name, d["aid"]), d["cover"])
        for i,v in enumerate(d["pics"]):
            down_pic("%s-%s-%d.jpg" % (name, d["aid"], i), v) 


def down_pic(name, pic_url):
    print name, pic_url
    if os.path.exists(name):
        return 
    res = simple_http.get(pic_url, proxy=proxy)
    if res["status"] != 200:
        print "skip", pic_url
        return
    try:
        f = open(name, "wb+") 
    except IOError:
        f = open(name.split("-")[-1], "wb+")
    f.write(res["text"])
    f.close() 


def down_list_dvd(author_url): 
    work_list = get_work_list(author_url) 
    for _, work_url, alias in work_list: 
        d = get_info(work_url) 
        name = d["name"]
        if not name:
            name = alias
        if d["cover"]:
            down_pic("%s-%s-cover.jpg" % (name, d["aid"]), d["cover"])
        for i,v in enumerate(d["pics"]):
            down_pic("%s-%s-%d.jpg" % (name, d["aid"], i), v) 


if __name__ == "__main__": 
    import sys, argparse
    parser = argparse.ArgumentParser(
            description="dmm downloader") 
    parser.add_argument("-c", type=str, help="dvd or digital") 
    parser.add_argument("-p", type=str, help="proxy") 
    parser.add_argument("-x", type=str, help="url type digital") 
    parser.add_argument("-w", type=str, help="url type dvd") 
    args = parser.parse_args()
    proxy = args.p
    if args.c:
        if args.c == "dvd":
            get_category_dvd()
        elif args.c == "digital":
            get_categroy_digital() 
    if args.x:
        down_list_digital(args.x)
    if args.w:
        down_list_dvd(args.w)

