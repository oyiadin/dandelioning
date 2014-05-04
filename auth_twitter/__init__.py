import json
from auth import oauth
from config import config

request_token_url = 'https://api.twitter.com/oauth/request_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'
access_token_url = 'https://api.twitter.com/oauth/access_token'

def auth(instance, action):
    params = dict(
        consumer_key=config['auth']['twitter']['consumer_key'],
        consumer_secret=config['auth']['twitter']['consumer_secret'],
        signature_method='HMAC-SHA1',
    )

    if action == 'authorize':
        token_info = oauth.string_to_dict(oauth.get_request_token(
            request_token_url, callback=config['auth']['twitter']['callback'],
            **params))

        if not token_info.get('oauth_callback_confirmed'):
            instance.write('cannot get request token')
            return

        instance.redirect(
            authorize_url + '?oauth_token=%s' % token_info['oauth_token'])

    elif action == 'callback':
        user = oauth.string_to_dict(oauth.get_access_token(
            access_token_url,
            oauth_verifier=instance.get_argument('oauth_verifier'),
            oauth_token=instance.get_argument('oauth_token'), **params))

        instance.set_secure_cookie('twitter_token', user['oauth_token'])
        instance.set_secure_cookie(
            'twitter_token_secret', user['oauth_token_secret'])

        instance.redirect('/')

    else:
        instance.write('unknown action')
