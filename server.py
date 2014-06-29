# coding=utf-8

import os
import sys
import urllib
import time
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.httpclient
import tornado.gen
import actions
from config import config
from infos import infos

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

oauth_1_providers = ('twitter',)
oauth_2_providers = ('weibo',)
providers = oauth_1_providers + oauth_2_providers


class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        accounts = {}
        for provider in providers:
            accounts[provider] = bool(
                self.get_cookie(provider + '_token'))

        self.render('index.html', accounts=accounts)


class AuthStepOneHandler(tornado.web.RequestHandler):
    def get(self, provider):
        if provider in oauth_1_providers:
            token = actions.get_request_token(provider)

            qs = urllib.urlencode({'oauth_token': token})

            self.redirect(
                infos[provider]['urls']['authorize'] + '?' + qs)

        elif provider in oauth_2_providers:
            qs = urllib.urlencode(dict(
                client_id=config['auth'][provider]['client_id'],
                redirect_uri=config['auth'][provider]['redirect_uri']))

            self.redirect(
                infos[provider]['urls']['authorize'] + '?' + qs)

        else:
            self.write('unsupported provider')
            self.finish()


class CallbackHandler(tornado.web.RequestHandler):
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
