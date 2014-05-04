import time
import random
import urllib
import hmac
import hashlib
import json
import tornado.httpclient
from auth import _request

def _oauth_header(**args):
    default_params = {
        'oauth_timestamp': str(int(time.time())),
        'oauth_nonce': hex(random.getrandbits(64))[2:-1],
        'oauth_version': '1.0'
    }

    args.update(default_params)

    return args

def _oauth_http_header(args, *extra_keys):
    params = _oauth_header(
        oauth_consumer_key=args['consumer_key'],
        oauth_signature_method=args['signature_method']
    )
    if args['callback']:
        params['oauth_callback'] = args['callback']

    for key in extra_keys:
        params[_quote(key)] = _quote(args[key])
    print 'params: %s\n' % params
    params['oauth_signature'] = _signature(
        args['signature_method'], args['url'], args['consumer_secret'], '',
        method='POST', **params)

    params_string = 'OAuth ' + ', '.join(['%s="%s"' % (
        key, _quote(params[key])) for key in params.keys()])
    print "{'Authorization': %s}\n" % params_string
    return {'Authorization': params_string}

def _quote(string):
    return urllib.quote(string, '~')

def _signature(signature_method, base_url, consumer_secret, token_secret,
               method='POST', **args):
    if signature_method == 'HMAC-SHA1':
        params_list = []

        for key in sorted(args.keys()):
            params_list.append((_quote(key), _quote(args[key])))

        params_string = '&'.join(
            ['%s=%s' % (key, value) for key, value in params_list])
        base_string = '&'.join(
            (method, _quote(base_url), _quote(params_string)))

        key = consumer_secret + '&' + token_secret

        return hmac.new(str(key), str(base_string), hashlib.sha1) \
            .digest().encode('base64').rstrip()

def string_to_dict(string):
    _dict = {}

    for param in string.split('&'):
        key, value = param.split('=')
        _dict[key] = value

    return _dict

def get_request_token(url, consumer_key, consumer_secret, signature_method,
                      callback=''):
    request = _request(url, 'POST',
        headers=_oauth_http_header(vars()), body='')

    response = tornado.httpclient.HTTPClient().fetch(request)

    return response.body

def get_access_token(url, consumer_key, consumer_secret, signature_method,
                     oauth_verifier, oauth_token, callback=''):
    request = _request(url, 'POST',
        headers=_oauth_http_header(vars(), 'oauth_verifier', 'oauth_token'),
        body='')

    response = tornado.httpclient.HTTPClient().fetch(request)

    return response.body
