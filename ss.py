import pdb
from lxml import etree
import json
import os.path
import simple_http 

base = "http://sexinsex.net/bbs/"

p_xpath = "/html/body/div[4]/div/div[4]/div/div[8]/form/table/table/table/table/tbody/tr/th/span[1]/a"

p2_xpath = "/html/body/div[4]/div/div[4]/div/div[8]/form/table/table/tbody/tr/th/span[1]/a"

img_xpath = "/html[1]/body/div[4]/div[1]/div[4]/div[1]/form/div[1]/table/tr[1]/td[2]/div[3]/div[3]/font[1]/font/img"

img2_xpath = "/html[1]/body/div[4]/div[1]/div[4]/div[1]/form/div[1]/table/tr[1]/td[2]/div[3]/div[3]/img"

torrent_xpath = "/html[1]/body/div[4]/div[1]/div[4]/div[1]/form/div[1]/table/tr[1]/td[2]/div[3]/div[4]/dl/dt/a[1]"

thread = { 
        "asia_soft": "230",
        "asia_hard": "143",
        "western": "229",
        "comic": "231",
        "asia_soft_redir": "58",
        "asia_hard_redir": "25",
        "western_redir": "77",
        "comic_redir": "27" 
        } 


proxy = None

def sis_login(user, password):
    res = simple_http.get(base+"logging.php?action=login", proxy=proxy, timeout=10)
    t = etree.HTML(res["text"].decode("gbk"))
    formhash = t.xpath("/html/body/div[4]/div[1]/div[4]/div[1]/form/input[1]")[0].attrib["value"].encode("utf-8")
    referer = t.xpath("/html/body/div[4]/div[1]/div[4]/div[1]/form/input[2]")[0].attrib["value"].encode("utf-8")
    payload = {
            "formhash": formhash,
            "referer":  base+referer,
            "cookietime": "2592000",
            "loginfield": "username",
            "username": user,
            "password": password,
            "questionid": "",
            "answer": "",
            "loginsubmit": "true"
            } 
    res = simple_http.post(base+ "logging.php?action=login", proxy=proxy, payload = payload, timeout=10)
    return simple_http.get_cookie(res["cookie"])


def down_one(title, url):
    res = simple_http.get(url, proxy=proxy, timeout=20, cookie=cookie)
    if not res:
        return
    if res["status"] != 200:
        return
    t = etree.HTML(res["text"]) 
    pics = t.xpath(img_xpath) + t.xpath(img2_xpath) 
    torrent = [x for x in t.xpath(torrent_xpath) if x.attrib["href"].startswith("attach")] 
    for i,v in enumerate(pics):
        name = ("%s-%d.jpg" % (title, i)).replace("/", "-")
        if os.path.exists(name):
            continue
        if not "jpg" in v.attrib["src"]:
            continue
        try:
            res = simple_http.get(v.attrib["src"], proxy=proxy, redirect=10) 
        except socket.timeout:
            continue 
        if len(res["text"]) < 10240:
            continue
        try:
            f = open(name, "wb+")
        except IOError as e:
            print e
            continue
        f.write(res["text"])
        f.close()
    for i,v in enumerate(torrent):
        name = ("%s-%d.torrent" % (title, i)).replace("/", "-") 
        if os.path.exists(name):
            continue 
        res = simple_http.get(base+v.attrib["href"], proxy=proxy, cookie=cookie, timeout=20)
        if res["status"] != 200:
            continue
        try:
            f = open(name, "wb+")
        except IOError as e:
            print e
            continue
        f.write(res["text"])
        f.close() 


def get_content(title, url): 
    res = simple_http.get(base+url, cookie=cookie, proxy=proxy, timeout=10)
    t = etree.HTML(res["text"]) 
    down_one(title, base+url)


def get_page(t, i): 
    url = "%sforum-%s-%d.html" % (base, t, i)
    res = simple_http.get(url, cookie = cookie, proxy=proxy, timeout=10) 
    t = etree.HTML(res["text"].decode("gbk", "ignore")) 
    al = t.xpath(p_xpath)+t.xpath(p2_xpath)
    for i,v in enumerate(al):
        print "[%d/%d] %s" % (i+1, len(al), v.text)
        get_content(v.text, v.attrib["href"])


if __name__ == "__main__":
    import sys, argparse
    parser = argparse.ArgumentParser(
            description="torrent downloader")
    parser.add_argument("-t", type=str, help="set thread")
    parser.add_argument("-i", type=int, help="page id")
    parser.add_argument("-p", type=str, help="proxy")
    args = parser.parse_args() 
    proxy = args.p
    if os.path.exists("sis_cookie"):
        cookie = json.loads(open("sis_cookie").read())
    else: 
        cookie = sis_login("r1osrb", "1234567") 
        f = open("sis_cookie", "w+")
        f.write(json.dumps(cookie))
        f.close() 
    if args.t: 
        get_page(thread[args.t], args.i) 
