import sys
import json
import time
import hmac
import urllib
import base64
import random
import hashlib
import urlparse
import tornado.web
import tornado.gen
import tornado.log
import tornado.ioloop
import tornado.httputil
import tornado.httpclient
from g import g
from config import config as c

GET = 'GET'
POST = 'POST'
OAUTH_1 = 'OAUTH_1'
OAUTH_2 = 'OAUTH_2'

reload(sys)
sys.setdefaultencoding('utf-8')
tornado.httpclient.AsyncHTTPClient.configure(
    "tornado.curl_httpclient.CurlAsyncHTTPClient")
client = tornado.httpclient.AsyncHTTPClient()


class BaseHandler(tornado.web.RequestHandler):
    def get(self, path=''):
        self.write('GET method is not supported for this path.')
        self.finish()

    def post(self, path=''):
        self.write('POST method is not supported for this path.')
        self.finish()

    def render(self, template_name, **kwargs):
        super(BaseHandler, self).render(
            template_name,
            config=c, accounts=self.get_tokens())

    def error(self, err_msg='Something went wrong.'):
        self.write(err_msg)
        self.finish()

    def get_tokens(self):
        tokens = {}
        for provider in g['providers']:
            value = self.get_secure_cookie(provider + '_token')
            tokens[provider] = value

        return tokens

    def get_secrets(self):
        secrets = {}
        for provider in g['oauth_1_providers']:
            value = self.get_secure_cookie(provider + '_token_secret')
            secrets[provider] = value

        return secrets

    def parse_qs(self, qs):
        """ 'foo=bar&baz=%26' ----> {'foo': 'bar', 'baz': '&'} """

        result = {}
        pairs = qs.split('&')
        for key_value in pairs:
            kv = key_value.split('=')
            key = urlparse.unquote(kv[0])
            value = urlparse.unquote(kv[1])
            result[key] = value

        return result


class Request(object):
    def __init__(self, instance, provider='', token='', secret=''):
        self.instance = instance
        self.provider = provider
        self.token = token
        self.secret = secret
        self.urls = g[self.provider]['urls']
        self.auth = c['auth'][self.provider]

    def _quote(self, qs):
        """ 'a&b' ----> 'a%26b' """

        # The symbol '~' does not need to be replaced.
        return urllib.quote(str(qs), '~')

    def _gen_oauth_header(self, url, method, oauth_version,
                          oauth_headers={}, **headers):
        """Generate an OAuth header. Returns a
        dictionary which can be writen into HTTP Header."""

        if oauth_version == OAUTH_2:
            return {'Authorization': 'OAuth2 %s' % self.token} \
                if self.token else {}

        consumer_key = self.auth['consumer_key']
        consumer_secret = self.auth['consumer_secret']
        token_secret = self.secret

        default_headers = {
            'oauth_timestamp': str(int(time.time())),
            'oauth_nonce': hex(random.getrandbits(64))[2:-1],
            'oauth_version': '1.0',
            'oauth_consumer_key': consumer_key,
            # Now only support HAMC-SHA1.
            'oauth_signature_method': 'HMAC-SHA1',
        }
        oauth_headers.update(default_headers)
        if self.token:
            oauth_headers['oauth_token'] = self.token
        headers.update(oauth_headers)

        params_list = []
        for key in sorted(headers.keys()):
            params_list.append((self._quote(key), self._quote(headers[key])))
        params_string = '&'.join(
            ['%s=%s' % (key, value) for key, value in params_list])

        base_string = '&'.join([
            method, self._quote(url), self._quote(params_string)])

        key = self._quote(consumer_secret) + '&' + self._quote(token_secret)

        signature = base64.b64encode(
            hmac.new(key, base_string, hashlib.sha1).digest())
        del key

        oauth_headers['oauth_signature'] = signature

        header = 'OAuth ' + ', '.join(
            ['%s="%s"' % (self._quote(key), self._quote(oauth_headers[key]))
                for key in oauth_headers.keys()])

        return {'Authorization': header}

    def _gen_request(self, oauth_version, url, method,
                     oauth_headers={}, **kwargs):
        header = self._gen_oauth_header(
            url, method, oauth_version, oauth_headers, **kwargs)
        qs = urllib.urlencode(kwargs)

        if method == GET:
            url = url + '?' + qs
            body = ''
        elif method == POST:
            body = qs

        proxy_config = c['proxy'] if c['enable_proxy'] else {}

        return tornado.httpclient.HTTPRequest(
            url=url, method=method, headers=header, body=body,
            connect_timeout=c['connect_timeout'],
            request_timeout=c['request_timeout'], **proxy_config)

    def request_token(self):
        return self._gen_request(
            OAUTH_1, self.urls['request_token'], POST,
            oauth_headers={'oauth_callback': self.auth['callback']})

    def access_token(self):
        if self.provider in g['oauth_1_providers']:
            return self._gen_request(
                OAUTH_1, self.urls['access_token'], POST,
                oauth_headers={
                    'oauth_callback': self.auth['callback'],
                    'oauth_token': self.instance.get_argument('oauth_token'),
                    'oauth_verifier': self.instance.get_argument(
                        'oauth_verifier')})

        elif self.provider in g['oauth_2_providers']:
            return self._gen_request(
                OAUTH_2, self.urls['access_token'], POST,
                code=self.instance.get_argument('code'),
                client_id=self.auth['client_id'],
                client_secret=self.auth['client_secret'],
                redirect_uri=self.auth['redirect_uri'],
                grant_type='authorization_code')

    def update(self):
        status = self.instance.parse_qs(self.instance.request.body)['status']

        if self.provider in g['oauth_1_providers']:
            oauth_version = OAUTH_1
        else:
            oauth_version = OAUTH_2

        return self._gen_request(
            oauth_version, self.urls['update'], POST, status=status)


class IndexHandler(BaseHandler):
    def get(self):
        self.render('index.html')


class AuthStepOneHandler(BaseHandler):
    @tornado.gen.coroutine
    def get(self, provider):
        # For OAuth 1.0, get `request_token` then redirect to authorize url.
        # For OAuth 2.0, redirect to authorize url directly."""
        if self.get_cookie(provider + '_token'):
            self.redirect('/')
            return

        if provider in g['oauth_1_providers']:
            try:
                response = yield tornado.gen.Task(
                    client.fetch, Request(self, provider).request_token())
            except tornado.httpclient.HTTPError, err_msg:
                self.error(err_msg)
                return

            body = self.parse_qs(response.body)
            if not body.get('oauth_callback_confirmed'):
                self.error('Error: %s' % body)
                return

            qs = urllib.urlencode({'oauth_token': body['oauth_token']})

        elif provider in g['oauth_2_providers']:
            qs = urllib.urlencode(dict(
                client_id=c['auth'][provider]['client_id'],
                redirect_uri=c['auth'][provider]['redirect_uri']))

        else:
            self.error('Unsupported provider.')
            return

        self.redirect(g[provider]['urls']['authorize'] + '?' + qs)


class CallbackHandler(BaseHandler):
    @tornado.gen.coroutine
    def get(self, provider):
        # Get `access_token`, put it into cookie then redirect to `/`.
        try:
            response = yield tornado.gen.Task(
                client.fetch, Request(self, provider).access_token())
        except tornado.httpclient.HTTPError, err_msg:
            self.error(err_msg)
            return

        if provider in g['oauth_1_providers']:
            body = self.parse_qs(response.body)

            self.set_secure_cookie(
                '%s_token' % provider, body['oauth_token'])
            self.set_secure_cookie(
                '%s_token_secret' % provider, body['oauth_token_secret'])

        elif provider in g['oauth_2_providers']:
            body = json.loads(response.body)

            expires = body.get('expires_in') + time.time()
            self.set_secure_cookie(
                '%s_token' % provider, body['access_token'],
                expires=expires)

        else:
            self.error('Unsupported provider.')
            return

        self.redirect('/')


class APIHandler(BaseHandler):
    def finish(self, action, message='', **kwargs):
        self.write(dict(action=action, message=message, code='200', **kwargs))
        super(APIHandler, self).finish()

    def error(self, message='Something went wrong.', action='', code='400',
              **kwargs):
        self.write(dict(action=action, message=message, code=code, **kwargs))
        super(APIHandler, self).finish()

    @tornado.gen.coroutine
    def post(self, action):
        tokens = self.get_tokens()
        secrets = self.get_secrets()

        if action == 'update':
            responses = {}

            for provider in g['providers']:
                token = tokens.get(provider)
                secret = secrets.get(provider)

                if token:
                    try:
                        response = yield tornado.gen.Task(
                            client.fetch,
                            Request(self, provider, token, secret).update())
                    except tornado.httpclient.HTTPError, err_msg:
                        self.error(err_msg, 'update')
                        return

                    responses[provider] = response.body

        elif action == 'clear_accounts':
            self.clear_all_cookies()

        else:
            self.error('Unknown action.')
            return

        self.finish(action, **responses)


routers = [
    ('/', IndexHandler),
    ('/auth/1/(.*?)', AuthStepOneHandler),
    ('/auth/callback/(.*?)', CallbackHandler),
    ('/_/(.*?)', APIHandler),
]
application = tornado.web.Application(routers, **c)

if __name__ == '__main__':
    tornado.log.enable_pretty_logging()
    application.listen(c['port'])

    tornado.ioloop.IOLoop.instance().start()
