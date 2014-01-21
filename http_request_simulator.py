import os

import signal
import pdb
import time
import pprint 
from lxml import etree

import etree_utils
import simple_http

def getpage(url, nsecs=2):
    try:
        _, _, content = simple_http.get(url,
                proxy="socks5://127.0.0.1:9988")
    except Exception as e:
        raise Exception("request failed: %s error %s", (url, e)) 
    print "=========\npage done: %s\ntimeout: %ds\n=========" % (url, nsecs)
    t = etree.HTML(content) 
    urls = [] 
    host = simple_http.url_decode(url)["host"]
    #find all script, img
    for i in etree_utils.query_element(t, "[script,img]"): 
        attrib = i.attrib 
        if "href" in attrib: 
            url_dict = simple_http.url_decode(attrib["href"])
            if not url_dict["host"]:
                url_dict["host"] = host 
            urls.append(simple_http.url_encode(url_dict)) 
        if "src" in attrib: 
            url_dict = simple_http.url_decode(attrib["src"])
            if not url_dict["host"]:
                url_dict["host"] = host 
            urls.append(simple_http.url_encode(url_dict)) 
    #multiprocess get
    pids = []
    for i in urls:
        pid = os.fork()
        if not pid: 
            try:
                simple_http.get(i, proxy="socks5://127.0.0.1:9988")
                print "url done: %s" % i
            except Exception as e:
                print "url failed: %s" % i 
                print "error %s" % e
            exit(0)
        else:
            pids.append(pid) 
    #wait children for nsecs 
    def clean_children(signum, frame): 
        for i in urls: 
            pid, _, _ = os.wait3(os.WNOHANG)
            if pid:
                del pids[pids.index(pid)]
        #kill them if they are still in progress
        for i in pids: 
            os.kill(i, signal.SIGKILL)        
        for i in pids:
            os.wait()
        print "request done, kill %d children" % len(pids)
    signal.setitimer(signal.ITIMER_REAL, nsecs)
    signal.signal(signal.SIGINT, clean_children)
    signal.signal(signal.SIGALRM, clean_children)
    #block
    time.sleep(0xffff)

if __name__ == "__main__":
    import sys 
    getpage(sys.argv[1], nsecs=3)

