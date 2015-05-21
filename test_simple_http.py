import simple_http 

def test(case, code):
    if code():
        print "%s: ok" % case
    else:
        print "%s: failed" % case

cases = {}

def test_urls():
    pass
