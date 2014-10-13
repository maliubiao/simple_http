import os
import sys
import signal
import traceback
import pdb
import time
import pprint 
from lxml import etree

import etree_util
import simple_http

def getpage(url, nsecs=5):
    try:
        a = time.time()
        h, content = simple_http.get(url) 
    except Exception as e:
        raise Exception("request failed: %s error %s", (url, e)) 
    print "=========\npage done in %fs: %s\ntimeout: %ds\n=========" % (time.time() -a, url, nsecs) 
    try:
        t = etree.HTML(content) 
    except:
        print "fetch failed: %s" % url
        pprint.pprint(h)
        exit(1)
    urls = [] 
    host = simple_http.urlparse(url)["host"] 
    #find all script, img
    for i in etree_util.query_element(t, "[script,img,link]"): 
        attrib = i.attrib 
        if "href" in attrib: 
            url_dict = simple_http.urlparse(attrib["href"])
            if not url_dict["host"]:
                url_dict["host"] = host 
            urls.append(simple_http.generate_url(url_dict)) 
        if "src" in attrib: 
            url_dict = simple_http.urlparse(attrib["src"])
            if not url_dict["host"]:
                url_dict["host"] = host 
            urls.append(simple_http.generate_url(url_dict)) 
    #multiprocess get 
    pids = []
    for i in urls:
        pid = os.fork()
        if not pid: 
            try: 
                a = time.time()
                simple_http.get(i)
                print "url done in %fs %s" % (time.time() - a, i)
            except Exception as e:
                print "url failed: %s" % i 
                print "error %s" % e
                traceback.print_tb(sys.exc_info()[2])
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
    getpage(sys.argv[1], nsecs=5)

