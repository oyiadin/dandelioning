#coding=utf-8

import time
import random
import urllib
import urlparse
import json
import hmac
import hashlib
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.httpclient
import tornado.gen
from config import config

class BaseHandler(tornado.web.RequestHandler):
    def quote(self, string):
        # The symbol '~' does not need to be replaced
        return urllib.quote(string, '~')

    def httprequest(self, url, method, **kwargs):
        return tornado.httpclient.HTTPRequest(
            url=url, method=method,
            connect_timeout=config['connect_timeout'],
            request_timeout=config['request_timeout'], **kwargs)

    # Only OAuth 1.0 needs to send information in the http header
    def oauth_header(self, provider, method, base_url, token_secret='',
                     **kwargs):
        consumer_key = config['auth'][provider]['consumer_key']
        consumer_secret = config['auth'][provider]['consumer_secret']
        callback = config['auth'][provider]['callback']

        headers = {
            'oauth_timestamp': str(int(time.time())),
            'oauth_nonce': hex(random.getrandbits(64))[2:-1],
            'oauth_version': '1.0',
            'oauth_consumer_key': consumer_key,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_callback': callback }
        kwargs.update(headers)
        headers = kwargs

        params_list = []
        for key in sorted(kwargs.keys()):
            params_list.append(
                (self.quote(key), self.quote(kwargs[key])))
        params_string = '&'.join(
            ['%s=%s' % (key, value) for key, value in params_list])
        base_string = '&'.join(
            (method, self.quote(base_url), self.quote(params_string)) )

        key = str(consumer_secret + '&' + token_secret)
        signature = hmac.new(key, base_string, hashlib.sha1) \
            .digest().encode('base64').rstrip()

        headers['oauth_signature'] = signature

        header = 'OAuth ' + ', '.join([
            '%s="%s"' % (self.quote(key), self.quote(headers[key])) \
            for key in headers.keys()] )

        return {'Authorization': header}

class IndexHandler(BaseHandler):
    def get(self):
        accounts = {}
        for provider in ('twitter', 'weibo'):
            accounts[provider] = bool(
                self.get_cookie(provider + '_token'))

        self.render('index.html', accounts=accounts)

class AuthStepOneHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, provider):
        # OAuth 1.0
        if provider in ('twitter',):
            if provider == 'twitter':
                url_prefix = 'https://api.twitter.com/oauth/'
                url1 = url_prefix + 'request_token'
                url2 = url_prefix + 'authorize'

            client = tornado.httpclient.AsyncHTTPClient()
            header = self.oauth_header(
                provider=provider, method='POST', base_url=url1)

            request = self.httprequest(
                url=url1, method='POST', headers=header, body='')
            response = yield tornado.gen.Task(client.fetch, request)

            token = urlparse.parse_qs(response.body)

            if not token.get('oauth_callback_confirmed'):
                self.write('failed to get request token')
                return

            qs = urllib.urlencode({
                'oauth_token': token['oauth_token'][0]} )

            self.redirect(url2 + '?' + qs)

        # OAuth 2.0
        elif provider in ('weibo',):
            if provider == 'weibo':
                url = 'https://api.weibo.com/oauth2/authorize'

            qs = urllib.urlencode(dict(
                client_id=config['auth'][provider]['client_id'],
                redirect_uri=config['auth'][provider]['redirect_uri']))

            self.redirect(url + '?' + qs)

        else:
            self.write('unsupported provider')

class CallbackHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, provider):
        # OAuth 1.0
        client = tornado.httpclient.AsyncHTTPClient()
        if provider in ('twitter',):
            if provider == 'twitter':
                url = 'https://api.twitter.com/oauth/access_token'

            oauth_token = self.get_argument('oauth_token')
            oauth_verifier = self.get_argument('oauth_verifier')

            header = self.oauth_header(
                provider=provider, method='POST', base_url=url,
                oauth_token=oauth_token,
                oauth_verifier=oauth_verifier)

            request = self.httprequest(
                url=url, method='POST', headers=header, body='')
            response = yield tornado.gen.Task(client.fetch, request)
            token = urlparse.parse_qs(response.body)

            self.set_secure_cookie(
                'twitter_token', token['oauth_token'][0])
            self.set_secure_cookie(
                'twitter_token_secret', token['oauth_token_secret'][0])

            self.redirect('/')

        # OAuth 2.0
        elif provider in ('weibo',):
            code = self.get_argument('code')
            if provider == 'weibo':
                url = 'https://api.weibo.com/oauth2/access_token'

            config_auth = config['auth'][provider]
            qs = urllib.urlencode(dict(
                code=code,
                client_id=config_auth['client_id'],
                client_secret=config_auth['client_secret'],
                redirect_uri=config_auth['redirect_uri'],
                grant_type='authorization_code') )

            request = self.httprequest(url=url, method='POST', body=qs)
            response = yield tornado.gen.Task(client.fetch, request)
            user = json.loads(response.body)
            expires = user['expires_in'] + time.time()

            self.set_secure_cookie(
                'weibo_token', user['access_token'], expires=expires)

            self.redirect('/')

        else:
            self.write('unsupported provider')

routers = [
    ('/', IndexHandler),
    ('/auth/1/(.*?)', AuthStepOneHandler),
    ('/auth/callback/(.*?)', CallbackHandler),
]
application = tornado.web.Application(routers, **config)

if __name__ == '__main__':
    application.listen(config['port'])

    try:
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        pass
