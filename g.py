__all__ = ['g']

g = {
    'oauth_1_providers': ('twitter',),
    'oauth_2_providers': ('weibo',),
    'twitter': {
        "status_max_length": 140,
        "urls": {
            "request_token": "https://api.twitter.com/oauth/request_token",
            "authorize": "https://api.twitter.com/oauth/authorize",
            "access_token": "https://api.twitter.com/oauth/access_token",
            "update": "https://api.twitter.com/1.1/statuses/update.json"}},
    'weibo': {
        "status_max_length": 140,
        "urls": {
            "authorize": "https://api.weibo.com/oauth2/authorize",
            "access_token": "https://api.weibo.com/oauth2/access_token",
            "update": "https://api.weibo.com/2/statuses/update.json"}},
}

g['providers'] = g['oauth_1_providers'] + g['oauth_2_providers']
