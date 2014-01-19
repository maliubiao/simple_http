import http_stream_parser
import pprint

f = open("stream.test", "r")
h, c, b = http_stream_parser.parse(f.read()) 
f.close() 
pprint.pprint(h)
pprint.pprint(c)

