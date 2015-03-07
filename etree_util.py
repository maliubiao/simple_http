#! /usr/bin/env python
#-*-encoding=utf-8-*-

import re 
import sys 
from lxml import etree 
import pdb

def _match_one(tree, nodes, selector):
    elements = [] 
    prefix = selector[0]
    sc = selector[1:]
    #find by attr
    if prefix == ".": 
        parts = sc.split("-")
        if parts:
            cat = parts[0]
            value = "-".join(parts[1:])
        else:
            cat = "class",
            value = sc 
        selector = re.compile(value)
        for node in nodes: 
            v = node.attrib.get(cat, "") 
            if selector.findall(v):
                elements.append(node) 
    #find by line number
    elif prefix == ">":
        if "-" in selector:
            smin, smax = [int(x) for x in sc.split("-")]
        else:        
            smin = smax = int(sc)
        for _, node in etree.iterwalk(tree, tag="*", events=("start", )):
            line = node.sourceline
            if line >= smin and line <= smax:
                elements.append(node)
    #find by text
    elif prefix == "-": 
        for _, node in etree.iterwalk(tree, tag="*", events=("start", )): 
            if node.text and re.findall(sc.decode("utf-8"), node.text, re.UNICODE):
                elements.append(node) 
    #find by xpath
    elif prefix == ",":
        elements.extend(tree.xpath(sc))
    #find by tag
    else:
        for node in nodes:
            if selector == node.tag:
                elements.append(node)
    return elements 


def get_xpath(node): 
    return node.getroottree().getpath(node)
 


def query_element(content, selector): 
    tree = etree.HTML(content) 
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
    content = f.read()
    f.close() 
    arg1 = sys.argv[1] 
    selector = sys.argv[2] 
    for i in query_element(content, selector):
        print "==============="
        dump_node(i) 



if __name__ == "__main__":
    main()
