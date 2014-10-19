import simple_http
import pprint

default = "down.output"

def down(url, output, proxy=""):
    h, c = simple_http.get(url, proxy=proxy, header=simple_http.download_header)
    if h["status"] != 200:
        pprint.pprint(h)
        exit(1)
    f = open(output, "w+")
    f.write(c)
    f.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
            description="a simple tool for downloading")
    parser.add_argument("-u", type=str, help="target url")
    parser.add_argument("-p", type=str, help="proxy")
    parser.add_argument("-o", type=str, default=default, help="file name")
    args = parser.parse_args()
    if args.u:
        down(args.u, args.o, args.p)

