import time
import random
import urllib
import json
import hmac
import hashlib
import tornado.httpclient
from infos import infos
from config import config

__all__ = ['get_request_token', 'get_access_token', 'update']

oauth_1_providers = ('twitter',)
oauth_2_providers = ('weibo',)

client = tornado.httpclient.HTTPClient()


def _quote(string):
    # The symbol '~' does not need to be replaced
    return urllib.quote(string, '~')


def _parse_qs(qs):
    qs_dict = {}

    for pair in qs.split('&'):
        key, value = pair.split('=')
        qs_dict[urllib.unquote(key)] = urllib.unquote(value)

    return qs_dict


# Only OAuth 1.0 needs to send information in the http header
# By default, token_secret will be set to ''.
def _oauth_header(provider, method, base_url,
                  token_secret='', **kwargs):
    consumer_key = config['auth'][provider]['consumer_key']
    consumer_secret = config['auth'][provider]['consumer_secret']

    headers = {
        'oauth_timestamp': str(int(time.time())),
        'oauth_nonce': hex(random.getrandbits(64))[2:-1],
        'oauth_version': '1.0',
        'oauth_consumer_key': consumer_key,
        # Now only support the HAMC-SHA1 method
        'oauth_signature_method': 'HMAC-SHA1',
    }
    kwargs.update(headers)
    headers = kwargs

    params_list = []
    for key in sorted(kwargs.keys()):
        params_list.append(
            (_quote(key), _quote(kwargs[key])))
    params_string = '&'.join(
        ['%s=%s' % (key, value) for key, value in params_list])
    base_string = '&'.join((
        method,
        _quote(base_url),
        _quote(params_string)))

    key = str(consumer_secret + '&' + token_secret)
    signature = hmac.new(key, base_string, hashlib.sha1) \
        .digest().encode('base64').rstrip()
    del key

    headers['oauth_signature'] = signature

    header = 'OAuth ' + ', '.join([
        '%s="%s"' % (_quote(key), _quote(headers[key]))
        for key in headers.keys()])

    # Will write into http header
    return {'Authorization': header}


# Body must not be None for POST request
def _gen_request(body='', **kwargs):
    return tornado.httpclient.HTTPRequest(
        body=body,
        connect_timeout=config['connect_timeout'],
        request_timeout=config['request_timeout'], **kwargs)


def _oauth_1_request(url, method, provider,
                     access=[], header_keys={}, **kwargs):
    if access:
        header_keys['oauth_token'] = access[0][provider]
        token_secret = access[1][provider]
    else:
        token_secret = ''

    header_keys.update(kwargs)
    header = _oauth_header(
        provider, method, url,
        token_secret=token_secret, **header_keys)

    qs = urllib.urlencode(kwargs)

    request = _gen_request(
        url=url, method=method, headers=header, body=qs)
    response = client.fetch(request)

    if access:
        return json.loads(response.body)
    else:
        return _parse_qs(response.body)


def _oauth_2_request(url, method, access_token='', **kwargs):
    qs = urllib.urlencode(kwargs)
    header = {'Authorization': 'OAuth2 %s' % access_token} \
        if access_token else {}

    if method == 'GET':
        url = url + '?' + qs
        body = ''
    elif method == 'POST':
        body = qs

    request = _gen_request(
        url=url, method=method, headers=header, body=body)
    response = client.fetch(request)

    return json.loads(response.body)


def get_authorize_url(provider, token=''):
    """OAuth 1.0 and 2.0
    Returns an authorize url. The parameter `token` is required if
    provider use OAuth 1.0."""

    if provider in oauth_1_providers:
        qs = urllib.urlencode({'oauth_token': token})
        return infos[provider]['urls']['authorize'] + '?' + qs

    elif provider in oauth_2_providers:
        qs = urllib.urlencode(dict(
            client_id=config['auth'][provider]['client_id'],
            redirect_uri=config['auth'][provider]['redirect_uri']))
        return infos[provider]['urls']['authorize'] + '?' + qs


def get_request_token(provider):
    """OAuth 1.0 Only
    Request for a request_token and return it. And will return False
    if it fails."""

    token = _oauth_1_request(
        url=infos[provider]['urls']['request_token'],
        method='POST', provider=provider,
        header_keys={
            'oauth_callback': config['auth'][provider]['callback']
        })

    if not token.get('oauth_callback_confirmed'):
        return False
    return token['oauth_token']


def get_access_token(provider, get_argument):
    """Request for an access_token. Will return a dictionary which is
    paresd from HTTP response body."""

    if provider in oauth_1_providers:
        return _oauth_1_request(
            url=infos[provider]['urls']['access_token'],
            method='POST', provider=provider,
            header_keys={
                'oauth_token': get_argument('oauth_token'),
                'oauth_verifier': get_argument('oauth_verifier'),
                'oauth_callback': config['auth'][provider]['callback']
            })

    else:
        auth_config = config['auth'][provider]
        args = dict(
            code=get_argument('code'),
            client_id=auth_config['client_id'],
            client_secret=auth_config['client_secret'],
            redirect_uri=auth_config['redirect_uri'],
            grant_type='authorization_code')

        return _oauth_2_request(
            url=infos[provider]['urls']['access_token'],
            method='POST', **args)


def update(tokens, secrets, status):
    """Update a new status on providers which we have token. Return
    None if the action succeed."""

    for provider in tokens:
        if provider == 'twitter':
            if len(status) > infos['twitter']['status_max_length']:
                return 'Length of status is too long for twitter.'

            response = _oauth_1_request(
                url=infos['twitter']['urls']['update'],
                method='POST', provider='twitter',
                access=(tokens, secrets),
                status=status)

            if not response['id']:
                return 'Something went wrong.'

        elif provider == 'weibo':
            if len(status) > infos['weibo']['status_max_length']:
                return 'Length of status is too long for weibo.'

            response = _oauth_2_request(
                url=infos['weibo']['urls']['update'],
                method='POST', access_token=tokens['weibo'],
                status=status)

            if not response['id']:
                return 'Something went wrong.'
