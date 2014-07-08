# coding=utf-8

import os
import sys
import time
import copy
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.httpclient
import tornado.websocket
import actions
from config import config

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

oauth_1_providers = ('twitter',)
oauth_2_providers = ('weibo',)
providers = oauth_1_providers + oauth_2_providers

config_without_auth = copy.copy(config)
del config_without_auth['auth']


class BaseHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('POST method is not supported.')

    def post(self):
        self.write('POST method is not supported.')

    def get_tokens(self):
        tokens = {}
        for provider in providers:
            value = self.get_secure_cookie(provider + '_token')
            if value:
                tokens[provider] = value

        return tokens

    def get_secrets(self):
        secrets = {}
        for provider in oauth_1_providers:
            value = self.get_secure_cookie(provider + '_token_secret')
            if value:
                secrets[provider] = value

        return secrets

    def render(self, template_name, **kwargs):
        accounts = {}
        for provider in providers:
            accounts[provider] = bool(self.get_cookie(
                provider + '_token'))

        super(BaseHandler, self).render(
            template_name,
            config=config_without_auth, accounts=accounts)

    def get_header(self, name, default_value=None):
        return self.request.headers.get(name, default_value)


class IndexHandler(BaseHandler):
    def get(self):
        self.render('index.html')


class AuthStepOneHandler(BaseHandler):
    def get(self, provider):
        if provider in oauth_1_providers:
            token = actions.get_request_token(provider)
        elif provider in oauth_2_providers:
            token = ''
        else:
            self.write('unsupported provider')
            self.finish()

        self.redirect(actions.get_authorize_url(provider, token=token))


class CallbackHandler(BaseHandler):
    def get(self, provider):
        if provider in oauth_1_providers:
            token = actions.get_access_token(
                provider, self.get_argument)

            self.set_secure_cookie(
                'twitter_token', token['oauth_token'])
            self.set_secure_cookie(
                'twitter_token_secret', token['oauth_token_secret'])

            self.redirect('/')

        elif provider in oauth_2_providers:
            user = actions.get_access_token(
                provider, self.get_argument)

            expires = user['expires_in'] + time.time()

            self.set_secure_cookie(
                'weibo_token', user['access_token'], expires=expires)

            self.redirect('/')

        else:
            self.write('unsupported provider')
            self.finish()


class APIHandler(BaseHandler):
    def _write(self, code='200', message='', **kwargs):
        self.write(dict(
            code=code, message=message, **kwargs))

    def _error(self, message, code='400', **kwargs):
        self._write(message, code, **kwargs)

    def post(self, action):
        if action == 'update':
            tokens = self.get_tokens()
            secrets = self.get_secrets()
            status = unicode(self.get_header('status'))

            err_msg = actions.update(tokens, secrets, status=status)
            if not err_msg:
                self._write()
            else:
                self._error(err_msg)

        else:
            self._error('Unknown action.')

routers = [
    ('/', IndexHandler),
    ('/auth/1/(.*?)', AuthStepOneHandler),
    ('/auth/callback/(.*?)', CallbackHandler),
    ('/_/(.*?)', APIHandler),
]
application = tornado.web.Application(routers, **config)

if __name__ == '__main__':
    application.listen(config['port'])

    try:
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        pass
