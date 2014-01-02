#! /usr/bin/env python
import os
import pdb
import json
import signal
import _proc
import umysql
import nonblocking
import os.path

myport = 8800
mycpu = 0

mycon = umysql.Connection() 
#default connection

def sigusr1_handler(signum, frame):
    print "cons: ", len(nonblocking.cons) 
    print "worker at %d on cpu %d" % (myport, mycpu)

def home_get(request, response): 
    response.update({ 
            "header": {
                "status": 403,
                "Content-Encoding": "gzip",
                "Content-Type": "text/html", 
                },
            "stream": ""
            })

def home_post(request, response):
    request_stream = request["stream"] 
    if "host" in request_stream:
        try:
            host, port, user, passwd, db = request_stream.values()
        except:
            raise Exception((nonblocking.HTTP_LEVEL, 400))
        if mycon.is_connected():
            mycon.close()
        try:
            mycon.connect(host, port, user, passwd, db)
            result = ""
        except Exception, err:
            result = json.dumps(err.args)
        response.update({
            "header": {
                "status": 200,
                "Content-Encoding": "gzip",
                "Content-Type": "application/json"
                },
            "stream": result
            })
        return 
    if "sql" in request_stream: 
        if not mycon.is_connected():
            mycon.connect("localhost", 3306, "root", "########", "mysql")
        sql = request_stream["sql"] 
        try:
            query = mycon.query(sql)
            if isinstance(query, tuple):
                result = json.dumps(query)
            else:
                fields = json.dumps(query.fields)
                rows = json.dumps(query.rows) 
                result = json.dumps({"field": fields, "row": rows})
        except Exception, err:
            result = json.dumps(err.args)
        response.update({
            "header": {
                "status": 200,
                "Content-Encoding": "gzip",
                "Content-Type": "application/json" 
                },
            "stream": result
                }) 
    else: 
        raise Exception((nonblocking.HTTP_LEVEL, 400)) 

home_application = {
        "url": r"^/query$",
        "get": home_get,
        "post": home_post 
        }

nonblocking.install(home_application)
nonblocking.install_statics("ui", os.path.abspath("./statics"), nonblocking.STATICS_PRELOAD)

try:
    _proc.setrlimit(_proc.RLIMIT_NOFILE, (10240, 20480))
except OSError, err:
    print "setrlimit failed, quit: %s" % str(err)
    exit(0)

signal.signal(signal.SIGUSR1, sigusr1_handler)
nonblocking.log_level = nonblocking.LOG_ERR|nonblocking.LOG_WARN

nonblocking.run_as_user("richard_n")
nonblocking.server_config() 
nonblocking.daemonize() 

nonblocking.poll_open(("localhost", 8800)) 
print "worker at %d on cpu %d" % (8800, 0)
nonblocking.poll_wait()

