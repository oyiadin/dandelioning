import json
import os
import sys

__all__ = ['config']

CONFIG = 'config.json'

if not os.path.isfile(CONFIG):
    print('Cannot find `config.json`. Exit now.')
    sys.exit(-1)

config = json.load(open(CONFIG))
