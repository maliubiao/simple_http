#-*-encoding=utf-8*-
from lxml import etree 

def new_tree(html, codec="utf-8"): 
    f = open(html, "r")
    d = f.read().decode(codec)
    f.close()
    t = etree.HTML(d) 
    return t


def utf8(v):
    return v.encode("utf-8") 


blank = {
        "\r": None,
        "\n": None,
        " ": None,
        "\t": None
        } 

def skip_NUL(s): 
    return "".join([x for x in s if x not in blank])


def generate_one(buf, n, indent, node): 
    if not isinstance(node.tag, basestring):
        return
    buf.append(n*indent)
    attrs = node.attrib.items() 
    if attrs:
        buf.append("<%s " % utf8(node.tag))
    else:
        buf.append("<%s" % utf8(node.tag))
    for k,v in attrs: 
        buf.append("%s=\"%s\" " % (utf8(k), utf8(v).replace("\"", "\\\"")))        
    buf.append(">\n") 
    text = skip_NUL(utf8(node.text))
    if text:
        buf.append((n+1) * indent + text+"\n") 

def generate(tree, indent):
    s1 = [[tree, 0]]
    s2 = [tree] 
    buf = []
    while s1: 
        node = s2.pop()
        try: 
            generate_one(buf, len(s1) - 1, indent, node) 
        except:
            pass
        total = node.getchildren() 
        totallen = len(total) 
        #有子
        if totallen:
            #记下sibling
            s1[-1][1] += 1 
            s1.append([total[0], 0])
            #入第一个子
            s2.append(total[0]) 
        #无子
        else: 
            #移到sibling 
            while True:
                if not s1:
                    break
                p, c = s1[-1] 
                cn = p.getchildren()
                #有sibling 
                if c < len(cn):
                    s2.append(cn[c])
                    s1[-1][1] += 1 
                    s1.append([cn[c], 0])
                    break 
                #无sibling
                else:
                    p, c = s1.pop()
                    if isinstance(node.tag, basestring): 
                        buf.append(len(s1) * indent + "</%s>\n" % utf8(p.tag))

    return "".join(buf)

if __name__ == "__main__":
    import sys
    print generate(new_tree(sys.argv[1]), "  ")
