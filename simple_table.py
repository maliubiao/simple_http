from random import randrange 
import marshal
from string import maketrans

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

def make_table(SD, DS): 
    tSD = maketrans("".join([chr(x) for x in SD.keys()]), 
        "".join([chr(x) for x in SD.values()]))
    tDS = maketrans("".join([chr(x) for x in DS.keys()]), 
        "".join([chr(x) for x in DS.values()]))
    return tSD, tDS 


def test(SD, DS):
    for i in range(0x0, 0xff+1):
        if i not in SD:
            return -1
        if i not in DS:
            return -1
    for k,v in SD.items():
        if k != DS[v]:
            return -1
    return 0


if __name__ == "__main__":
    SD, DS = generate()
    if test(SD, DS) < 0:
        print "test failed"
        exit()
    f = open("key", "w+")
    f.write(marshal.dumps(make_table(SD, DS)))
    f.close()

