import re 
import sys 
from lxml import etree 

def _match_one(tree, nodes, selector):
    elements = [] 
    if selector.startswith("."):
        selector = re.compile(selector[1:])
        for node in nodes: 
            attrib = node.attrib
            if "class" in attrib:
                if selector.match(attrib["class"]):
                    elements.append(node) 
    elif selector.startswith("#"):
        selector = re.compile(selector[1:])
        for node in nodes:
            attrib = node.attrib
            if "id" in attrib: 
                if selector.match(attrib["id"]):
                    elements.append(node) 
    elif "=" in selector:
        key, value = [x.strip() for x in selector.split("=")]
        selector = re.compile(value)
        for node in nodes:
            attrib = node.attrib
            if key in attrib: 
                if selector.match(attrib[key]):
                    elements.append(node) 
    elif selector.startswith(">"): 
        if "-" in selector:
            smin, smax = [int(x) for x in selector[1:].split("-")]
        else:
            smin = smax = int(selector[1:]) 
        for _, node in etree.iterwalk(tree, tag="*", events=("start", )):
            line = node.sourceline
            if line >= smin and line <= smax:
                elements.append(node)
    else:
        for node in nodes:
            if selector == node.tag:
                elements.append(node)
    return elements 

def get_xpath(node): 
    return node.getroottree().getpath(node)
 
def query_element(tree, selector): 
    elements = []
    nodes = [] 
    for _, node in etree.iterwalk(tree, tag="*", events=("start", )):
        nodes.append(node) 
    if selector.startswith("["):
        for x in selector.strip("[").strip("]").split(","):
            elements.extend(_match_one(tree, nodes, x.strip())) 
    else:
        elements.extend(_match_one(tree, nodes, selector))
    return elements
       
def toutf8(s):
    if isinstance(s, unicode):
        return s.encode("utf-8")
    return s

def dump_node(node):   
    print "tag: %s\n, line: %d\n, attrib: %s\n, text: %s\n, xpath: %s" % (
            toutf8(node.tag), node.sourceline, str(node.attrib), toutf8(node.text), get_xpath(node))

def main(): 
    if len(sys.argv) < 3:
        print "usage etree_utils.py htmlfile selector"
        exit(0)
    f = open(sys.argv[1], 'r')
    s = etree.HTML(f.read())
    f.close() 
    for i in query_element(s, sys.argv[2]):
        print "==============="
        dump_node(i)

if __name__ == "__main__":
    main()
