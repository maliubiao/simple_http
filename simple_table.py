from random import randrange 
from cStringIO import StringIO

def generate(): 
    SD = {}
    DS = {} 
    for i in range(0x0, 0xff+1): 
        d = randrange(0x0, 0xff+1) 
        found = False
        for j in range(d, 0xff+1): 
            if j not in DS:
                SD[i] = j
                DS[j] = i
                found = True
                break
        if not found:
            for k in range(0x0, d):
                if k not in DS:
                    SD[i] = k
                    DS[k] = i
                    found = True
                    break 
    return SD, DS

def translate(SD, data):
    buf = StringIO()
    for i in bytearray(data):
        buf.write(chr(SD[i]))         
    final = buf.getvalue()
    buf.close()
    return final

def test(SD, DS):
    for i in range(0x0, 0xff+1):
        if i not in SD:
            print "failed"
        if i not in DS:
            print "failed"
    for k,v in SD.items():
        if k != DS[v]:
            print "not equeal", k, v
    print "OK"



