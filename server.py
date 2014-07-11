# coding=utf-8

import os
import sys
import time
import copy
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.httpclient
import tornado.log
import actions
from config import config
from infos import infos

reload(sys)
sys.setdefaultencoding('UTF-8')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

oauth_1_providers = infos['oauth_1_providers']
oauth_2_providers = infos['oauth_2_providers']
providers = infos['providers']

config_without_auth = copy.copy(config)
del config_without_auth['auth']

tornado.log.enable_pretty_logging()


class BaseHandler(tornado.web.RequestHandler):
    def get(self, path=''):
        self.write('GET method is not supported.')

    def post(self, path=''):
        self.write('POST method is not supported.')

    def get_something(self, type):
        if type == 'tokens':
            suffix = '_token'
        elif type == 'secrets':
            suffix = '_token_secret'

        dict = {}
        for provider in providers:
            value = self.get_secure_cookie(provider + suffix)
            if value:
                dict[provider] = value

        return dict

    def get_tokens(self):
        return self.get_something('tokens')

    def get_secrets(self):
        return self.get_something('secrets')

    def render(self, template_name, **kwargs):
        accounts = {}
        for provider in providers:
            value = self.get_secure_cookie(provider + '_token')
            accounts[provider] = value

        super(BaseHandler, self).render(
            template_name,
            config=config_without_auth, accounts=accounts)

    def error_not_supported(self, err_type='provider'):
        err_type = err_type.capitalize()
        self.write('%s is not supported.' % err_type)


class IndexHandler(BaseHandler):
    def get(self):
        self.render('index.html')


class AuthStepOneHandler(BaseHandler):
    def get(self, provider):
        if self.get_cookie(provider + '_token'):
            self.redirect('/')
            return

        if provider in oauth_1_providers:
            res = actions.get_request_token(provider)
        elif provider in oauth_2_providers:
            res = ''
        else:
            self.error_not_supported()

        if isinstance(res, actions.Error):
            self.write(res.err_msg)
            return
        else:
            # For OAuth 2.0, the parameter `token` can be empty.
            self.redirect(
                actions.get_authorize_url(provider, token=res))


class CallbackHandler(BaseHandler):
    def get(self, provider):
        if provider in oauth_1_providers:
            res = actions.get_access_token(
                provider, self.get_argument)

            if isinstance(res, actions.Error):
                self.write(res.err_msg)
                return
            else:
                self.set_secure_cookie(
                    'twitter_token', res['oauth_token'])
                self.set_secure_cookie(
                    'twitter_token_secret', res['oauth_token_secret'])

        elif provider in oauth_2_providers:
            res = actions.get_access_token(
                provider, self.get_argument)

            if isinstance(res, actions.Error):
                self.write(res.err_msg)
                return
            else:
                expires = res['expires_in'] + time.time()

                self.set_secure_cookie(
                    'weibo_token',
                    res['access_token'], expires=expires)

        else:
            self.error_not_supported()
            return

        self.redirect('/')


class RevokeHandler(BaseHandler):
    def get(self, provider):
        if provider == 'all':
            self.clear_all_cookies()
        else:
            if provider in providers:
                if provider in oauth_1_providers:
                    self.clear_cookie(provider + '_token_secret')
                self.clear_cookie(provider + '_token')

        self.redirect('/')
    # Haven't finished yet.


class APIHandler(BaseHandler):
    def _write(self, action='', code='200', **kwargs):
        self.write(dict(
            code=code, action=action, **kwargs))

    def _error(self, message='', action='', code='400', **kwargs):
        self._write(action, code, message=message, **kwargs)

    def post(self, action):
        if action == 'update':
            tokens = self.get_tokens()
            secrets = self.get_secrets()

            res = actions.update(
                tokens, secrets, qs=self.request.body)
            if isinstance(res, actions.Error):
                self._error(res.err_msg, action)
                return
            else:
                self._write(action)

        else:
            self._error('Unknown action.')


routers = [
    ('/', IndexHandler),
    ('/auth/1/(.*?)', AuthStepOneHandler),
    ('/auth/callback/(.*?)', CallbackHandler),
    ('/auth/revoke/(.*?)', RevokeHandler),
    ('/_/(.*?)', APIHandler),
]
application = tornado.web.Application(routers, **config)

if __name__ == '__main__':
    application.listen(config['port'])

    try:
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        print 'Got a KeyboardInterrupt exception, exit now.'
