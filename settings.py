# -*- coding:utf-8 -*-

import tornado
import tornado.template
import os
from tornado.options import define, options


# 添加项目中的python模块到PYTHONPATH
import environment

# 添加path相对路径支持.
path = lambda root, *a: os.path.join(root, *a)

# 初始化配置
import ConfigParser
config = ConfigParser.ConfigParser()
ROOT = os.path.dirname(os.path.abspath(__file__))
CONF_FILE = os.path.join(ROOT, "confs/work_flow_engine.conf")
config.read(CONF_FILE)

# 数据库设置
DB_NAME = config.get('db', 'database')
DB_USER = config.get('db', 'user')
DB_PASS = config.get('db', 'password')
DB_HOST = config.get('db', 'host')
DB_PORT = config.get('db', 'port')
if DB_NAME and DB_USER and DB_PASS and DB_HOST and DB_PORT:
    USE_DB = 'mysql'
    DATABASE_URI = 'mysql+mysqldb://%s:%s@%s:%s/%s' % (DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME)
else:
    USE_DB = 'sqlite'
    DATABASE_URI = 'sqlite:///' + os.path.join(ROOT, 'data-test.sqlite')

# tornado 相关的设置
SECRET_KEY = config.get('app', 'secret_key')
define("port", default=8888, help="run on the given port", type=int)
define("config", default=None, help="tornado config file")
define("debug", default=True, help="debug mode")
tornado.options.parse_command_line()

# tornado 执行长链接任务时线程池大小
THREAD_POOL_MAX = 100

# Ansible Playbook Directory
PLAYBOOK_DIR = os.path.join(ROOT, "ansible_playbooks")
SSH_KEY_DIR = os.path.join(ROOT, "cache_keys")
if not os.path.exists(PLAYBOOK_DIR):
    os.mkdir(PLAYBOOK_DIR)
if not os.path.exists(SSH_KEY_DIR):
    os.mkdir(SSH_KEY_DIR)

# 配置日志
from logconfig.logconfig import init_logging
init_logging()

# tornado 其他参数的设置
settings = {}
settings['xsrf_cookies'] = False
# See PEP 391 and logconfig for formatting help.  Each section of LOGGERS
# will get merged into the corresponding section of log_settings.py.
# Handlers and log levels are set up automatically based on LOG_LEVEL and DEBUG
# unless you set them here.  Messages will not propagate through a logger
# unless propagate: True is set.

if options.config:
    tornado.options.parse_config_file(options.config)
