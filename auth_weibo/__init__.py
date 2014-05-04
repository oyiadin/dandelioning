import time
import json
from auth import oauth2
from config import config

authorize_uri = 'https://api.weibo.com/oauth2/authorize'
revoke_uri = 'https://api.weibo.com/oauth2/revokeoauth2'
access_token_uri = 'https://api.weibo.com/oauth2/access_token'

def auth(instance, action):
    if action == 'authorize':
        oauth2.authorize_redirect(
            instance, uri=authorize_uri,
            client_id=config['auth']['weibo']['client_id'],
            redirect_uri=config['auth']['weibo']['redirect_uri'])

    elif action == 'callback':
        code = instance.get_argument('code')

        if not code:
            instance.write('no code')
            return

        user = json.loads(oauth2.get_authenticated_user(code=code,
            uri=access_token_uri, **config['auth']['weibo']))
        expires = user['expires_in'] + time.time()

        instance.set_secure_cookie(
            'weibo_token', user['access_token'], expires=expires)
        instance.redirect('/')

    elif action == 'revoke':
        access_token = instance.get_secure_cookie('weibo_token')

        if access_token:
            result = oauth2.revoke(revoke_uri, access_token)

            if result is True:
                instance.write('revoke successfully')
                instance.clear_cookie('weibo_token')
                instance.redirect('/')

            else:
                isntance.write('failed: %s' % result)

    else:
        instance.write('unknown action')
