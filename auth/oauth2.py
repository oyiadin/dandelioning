import urllib
import json
import tornado.httpclient
from config import config
from auth import _request

__all__ = ['authorize_redirect', 'revoke', 'get_authenticated_user']

def _urlencode(_vars, *_keys):
    _dict = {}

    for _key in _keys:
        _dict[_key] = _vars[_key]

    return urllib.urlencode(_dict)

def authorize_redirect(instance, uri, client_id, redirect_uri, **kwargs):
    args = _urlencode(vars(), 'client_id', 'redirect_uri')

    instance.redirect(uri + '?' + args)

def revoke(uri, access_token, **kwargs):
    args = _urlencode(vars(), 'access_token')

    response = tornado.httpclient.HTTPClient() \
        .fetch(_request(uri, 'POST', body=args))
    body = json.loads(response.body)

    return True if body.get('result') else body.get('error', False)

def get_authenticated_user(code, client_id, client_secret,
                           uri, redirect_uri,
                           grant_type='authorization_code', **kwargs):
    args = _urlencode(vars(),
                     'code', 'client_id', 'client_secret',
                     'redirect_uri', 'grant_type')

    response = tornado.httpclient.HTTPClient() \
        .fetch(_request(uri, 'POST', body=args))

    return response.body
