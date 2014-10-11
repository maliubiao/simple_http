import simple_http
import pdb 
import pprint
import json 
import os.path
from collections import OrderedDict
import argparse
import socket

from lxml import etree 

SONGID_XPATH = "/html/body/div/ul/li/div/span[5]/a" 
LIMIT = 100

def get_songlink(songid): 
    ret = []
    p = {
            "songids": songid
            } 
    h, c = simple_http.post("http://play.baidu.com/data/music/songlink", payload = p) 
    for i in json.loads(c)["data"]["songList"]:
        if not i["songName"]:
            continue
        ret.append((i["songName"], i["songLink"])) 
    return ret

def get_songlinks(songs):
    ret = []
    groups = [] 
    ng = len(songs) / LIMIT
    if len(songs) % LIMIT:
        ng += 1
    for i in range(ng):
        groups.append(",".join([song[1].strip("/song/") for song in songs[i*LIMIT:LIMIT*(i+1)]])) 
    for g in groups:
        ret.extend(get_songlink(g))
    return ret

def get_songids(uid): 
    ret = []
    for i in range(0xffff):
        query = {
                "start": str(i * 25),
                "ting_uid": uid,
                "order": "hot"
                } 
        h, c =simple_http.get("http://music.baidu.com/data/user/getsongs", query=query); 
        if h["status"] != 200:
            break
        t = json.loads(c)["data"]["html"] 
        tree = etree.HTML(t)
        result = [x for x in tree.xpath(SONGID_XPATH)]
        if not result:
            break 
        for i in result:
            if not "class" in i.attrib:
                ret.append((i.attrib["title"], i.attrib["href"].split("#")[0]))
    return ret

def download_link(name, link): 
    h, c = simple_http.get(link, header=simple_http.download_header)
    if h["status"] != 200:
        if h["status"] == 302:
            h, c = simple_http.get(h["Location"], header=simple_http.download_header)
            if h["status"] != 200:
                pdb.set_trace() 
    f = open(name, "w+")
    f.write(c)
    f.close() 

def download_author(uid): 
    dup = OrderedDict()
    jobs = get_songids(uid) 
    for k,v in jobs:
        if not k in dup:
            dup[k] = v
    jobs = dup
    for i,v in enumerate(jobs.items()): 
        try:
            link = get_songlink(v[1].strip("/song/"))[0] 
        except IndexError: 
            print "skip", v[0]
            continue
        if os.path.exists(link[0]+".mp3"):
            continue
        print "===================\n[%d/%d]: %s\n%s" % (i+1, len(jobs), link[0], link[1])
        while True:
            try:
                download_link(link[0]+".mp3", link[1])
            except socket.error:
                continue 
            except Exception:
                print "skip", link[0]
            break

if __name__ == "__main__":
    import sys
    parser = argparse.ArgumentParser(
            description="baidu mp3 downloader") 
    parser.add_argument("-i", type=str, help="download by id")
    parser.add_argument("-a", type=str, help="download by author id")
    args = parser.parse_args()
    if args.i:
        ret = get_songlink(args.i) 
        if not ret:
            print "found nothing"
            exit(1)
        name, link = ret[0] 
        print name, "\n", link
        download_link(name+".mp3", link)
    elif args.a:
        download_author(args.a)
