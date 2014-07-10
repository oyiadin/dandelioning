__all__ = ['config']

import json
import os
import sys

_config = 'config.json'

if not os.path.isfile(_config):
    print 'Edit the example config file first, then run `mv config.json.example config.json`!'
    sys.exit(-1)

config = json.loads(open('config.json').read())
