__all__ = ['config']

import json

config = json.loads(open('config.json').read())
