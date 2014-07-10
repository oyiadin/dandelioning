import json
import os
import sys

__all__ = ['config']

CONFIG = 'config.json'

if not os.path.isfile(CONFIG):
    print 'Edit the example config file first, ' \
        'then run `mv config.json.example config.json`!'
    sys.exit(-1)

config = json.load(open(CONFIG))
