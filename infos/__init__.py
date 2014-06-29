import os
import json

os.chdir('infos')

__all__ = ['infos']
infos = {}

providers_list = ['twitter', 'weibo']

for provider in providers_list:
    data = open(provider + '.json').read()
    infos[provider] = json.loads(data)

os.chdir('..')
