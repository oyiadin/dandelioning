#coding=utf-8

import sys
import os
import tornado.ioloop
import tornado.web
import tornado.template
from config import config
import auth_weibo, auth_twitter

sys.path.append(os.path.abspath(__file__))

class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        if_auth = {}

        for provider in providers:
            if_auth[provider] = bool(
                self.get_cookie(provider + '_token'))

        self.render('index.html', if_auth=if_auth)

class AuthHandler(tornado.web.RequestHandler):
    def get(self, action, provider):
        if provider == 'weibo':
            auth_weibo.auth(self, action)
        elif provider == 'twitter':
            auth_twitter.auth(self, action)

        else:
            self.write('unknown service provider')

routers = [
    ('/', IndexHandler),
    ('/auth/(.*?)/(.*?)', AuthHandler)
]
application = tornado.web.Application(routers, **config)
providers = ('weibo', 'twitter')

if __name__ == '__main__':
    application.listen(config['port'])
    print 'Listening at port %s now' % config['port']

    try:
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        print 'Got a KeyboardInterrupt exception, will exit now'
