import tornado.httpclient
from config import config

def _request(uri, method, **kwargs):
    return tornado.httpclient.HTTPRequest(
        url=uri, method=method,
        connect_timeout=config['connect_timeout'],
        request_timeout=config['request_timeout'], **kwargs)
