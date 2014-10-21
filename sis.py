import simple_http
import pdb
import os.path
import socket
from lxml import etree

p1_xpath = "/html/body/div[4]/div/div[7]/form/table/table/table/table/table/tbody/tr/th/span[1]/a"
p1_special = "/html/body/div[4]/div/div[7]/form/table/table/table/table/tbody/tr/th/span[1]/a" 
pn_xpath = "/html/body/div[4]/div/div[7]/form/table/table/tbody/tr/th/span[1]/a"
torrent_xpath = "/html/body/div[4]/div[1]/form/div/table/tr[1]/td[2]/div[3]/div[4]/dl/dt/a"
image_xpath = "/html/body/div[4]/div[1]/form/div/table/tr[1]/td[2]/div[3]/div[3]/img"

base = "http://sis001.com/forum/"

thread_base = "http://sis001.com/forum/forum-%s-%d.html"

thread = { 
        "asia_soft": "230",
        "asia_hard": "143",
        "western": "229",
        "comic": "231",
        "asia_soft_redir": "58",
        "asia_hard_redir": "25",
        "western": "77",
        "comic_redir": "27" 
        } 

def down_one(title, url):
    h, c = simple_http.get(url, proxy=proxy)
    if not h:
        pdb.set_trace()
    if h["status"] != 200:
        pdb.set_trace()
    t = etree.HTML(c)
    pics = t.xpath(image_xpath)
    torrent = [x for x in t.xpath(torrent_xpath) if x.attrib["href"].startswith("attach")] 
    for i,v in enumerate(pics):
        name = ("%s-%d.jpg" % (title, i)).replace("/", "-")
        if os.path.exists(name):
            continue
        if not "jpg" in v.attrib["src"]:
            continue
        try:
            h, c = simple_http.get(v.attrib["src"], proxy=proxy) 
        except socket.timeout:
            continue
        if h["status"] != 200:
            if h["status"] == 302:
                h, c = simple_http.get(h["Location"], proxy=proxy)
                if h["status"] != 200:
                    pdb.set_trace()
        f = open(name, "w+")
        f.write(c)
        f.close()
    for i,v in enumerate(torrent):
        name = ("%s-%d.torrent" % (title, i)).replace("/", "-")
        if os.path.exists(name):
            continue
        h, c = simple_http.get(base+v.attrib["href"], proxy=proxy)
        if h["status"] != 200:
            pdb.set_trace()
        f = open(name, "w+")
        f.write(c)
        f.close()



def down_page(tid, pid): 
    h, c = simple_http.get(thread_base % (tid, pid), proxy=proxy)
    if h["status"] != 200:
        pdb.set_trace()
    t = etree.HTML(c) 
    url = []
    if pid == 1:
        a = t.xpath(p1_xpath)                 
        b = t.xpath(p1_special)
        url.extend(a)
        url.extend(b)
    else: 
        url.extend(t.xpath(pn_xpath)) 
    for i,v in enumerate(url): 
        try:
            down_one(v.text.encode("utf-8"), base + v.attrib["href"]) 
        except OSError: 
            print "skip, [p%d-%d]: %s" % (pid, i+1, v.text)
            continue
        print "[p%d-%d]: %s" % (pid, i+1, v.text)


if __name__ == "__main__":
    import sys, argparse
    parser = argparse.ArgumentParser(
            description="torrent downloader")
    parser.add_argument("-t", type=str, help="set thread")
    parser.add_argument("-i", type=int, help="page id")
    parser.add_argument("-p", type=str, help="proxy")
    args = parser.parse_args()
    if args.t: 
        proxy = args.p
        down_page(thread[args.t], args.i) 
