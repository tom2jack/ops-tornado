# -*- coding:utf-8 -*-
from __future__ import unicode_literals
import hashlib
import logging
from settings import SECRET_KEY

from uuid import uuid4
import jwt
from paramiko.rsakey import RSAKey
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import os
import json


logger = logging.getLogger('tornado.app')
options = {
    'verify_signature': True,
    'verify_exp': True,
    'verify_nbf': False,
    'verify_iat': True,
    'verify_aud': False
}


def get_md5(s):
    """
    hash　一段字符串
    Args:
        s: <string> 一段字符串
    Returns:
        digest: <str> hash过后的digest
    """
    m = hashlib.md5()
    m.update(s)
    return m.hexdigest()


def jwtauth(handler_class):
    """
    Handle Tornado JWT Auth
    """
    def wrap_execute(handler_execute):
        def require_auth(handler, kwargs):
            auth = handler.request.headers.get('Authorization')
            if auth:
                parts = auth.split()

                if parts[0].lower() != 'bearer':
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()
                elif len(parts) == 1:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()
                elif len(parts) > 2:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()

                token = parts[1]
                try:
                    jwt.decode(
                        token,
                        SECRET_KEY,
                        options=options
                    )

                except Exception, e:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write(e.message)
                    handler.finish()
            else:
                handler._transforms = []
                handler.write("Missing authorization")
                handler.finish()
            return True

        def _execute(self, transforms, *args, **kwargs):
            try:
                require_auth(self, kwargs)
            except Exception:
                return False

            return handler_execute(self, transforms, *args, **kwargs)
        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class


def gen_task_id():
    """
    use to generate task uuid.

    :return: <str> uuid
    """
    task_uuid = 'Task-' + uuid4().hex[:16]
    return task_uuid


class Dict(dict):
    """
    字典对象
    实现一个简单的可以通过属性访问的字典，比如 x.key = value
    """
    def __init__(self, names=(), values=(), **kw):
        super(Dict, self).__init__(**kw)
        for k, v in zip(names, values):
            self[k] = v

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(r"'Dict' object has no attribute '%s'" % key)

    def __setattr__(self, key, value):
        self[key] = value


def row2dict(row):
    d = {}
    for column in row.__table__.columns:
        d[column.name] = getattr(row, column.name)
    return d


def gen_keys(password=None, bits=2048):
    """
    generate an ssh key pair

    :param bits, <int> the key length
    :param password, <str> the private key password

    :return (<str>, <str>) (private key, public key)
    """
    s = StringIO()
    key = RSAKey.generate(bits)
    key.write_private_key(s, password)
    s.seek(0)
    private_key = s.read()
    pri = [key.get_name(), " ", key.get_base64(), " %s@%s" % ("jumpserver", os.uname()[1])]
    public_key = ''.join(pri)
    return private_key, public_key


def save_key_to_file(private_key, public_key, password=None, key_dir='/tmp'):
    """
    read the key string and save it to an file.

    :param private_key: <str> private key
    :param public_key: <str> public key
    :param password: the private key password
    :param key_dir: the directory to save keys
    :return: (<str>, <str>), (private key file path, public key file path)
    """
    private = StringIO()
    private.write(private_key)
    private.seek(0)
    if not os.path.exists(key_dir):
        os.mkdir(key_dir)

    private_file = os.path.join(key_dir, 'id_rsa')
    public_file = os.path.join(key_dir, 'id_rsa.pub')

    key = RSAKey.from_private_key(private, password)
    key.write_private_key_file(private_file, password)

    with open(public_file, 'w') as f:
        f.write(public_key)
        f.flush()

    return private_file, public_file


class CommonMiXin(object):

    def add_my_header(self):
        self.set_header('Content-Type', 'application/json; charset=UTF-8')

    def ImplementError(self):
        self.set_status(404)
        data = {
                "result": "This Method Not Implement!",
                "code": 404}
        logger.debug(data)
        self.write(json.dumps(data))
        self.finish()

    def my_response(self, code, data):
        if code == 200:
            self.write(json.dumps({"code": 200, "result": data}))
        else:
            self.write(json.dumps({"code": code, "result": data}))
        self.finish()


if __name__ == "__main__":
    pri, pub = gen_keys(password='test')
    print save_key_to_file(pri, pub, 'test')


