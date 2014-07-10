import os
import json

__all__ = ['infos']
infos = {}

files_list = ['providers', 'twitter', 'weibo']

for file in files_list:
    infos[file] = json.load(
        open(os.path.join('infos', file + '.json')))

infos['oauth_1_providers'] = infos['providers']['oauth_1']
infos['oauth_2_providers'] = infos['providers']['oauth_2']
infos['providers'] = \
    infos['oauth_1_providers'] + infos['oauth_2_providers']
