import json
from tornado.escape import to_basestring

def json_encode(value):
    return json.dumps(value).replace("</", "<\\/")

def json_decode(value):
    return json.loads(to_basestring(value))

