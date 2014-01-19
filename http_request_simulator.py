import os
import signal
import time
import pprint 
from lxml import etree

import etree_utils
import simple_http

def getpage(url, nsecs=2):
    try:
        _, _, content = simple_http.get(url)
    except:
        raise Exception("request failed: %s", url) 
    print "=========\npage done: %s\ntimeout: %ds\n=========" % (url, nsecs)
    t = etree.HTML(content) 
    urls = []
    #find all script, img
    for i in etree_utils.query_element(t, "[script,img]"): 
        attrib = i.attrib 
        if "href" in attrib: 
            urls.append(i.attrib["href"]) 
        if "src" in attrib: 
            urls.append(i.attrib["src"]) 
    #multiprocess get
    pids = []
    for i in urls:
        pid = os.fork()
        if not pid: 
            try:
                simple_http.get(i)
                print "url done: %s" % i
            except:
                print "url failed: %s" % i 
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

