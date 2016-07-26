# -*- coding:utf-8 -*-
from __future__ import unicode_literals

import hashlib
import json
import jwt
import datetime
from settings import SECRET_KEY
import logging
from tornado.web import RequestHandler
from model.models import DBSession, User

logger = logging.getLogger('tornado.app')


class AuthHandler(RequestHandler):

    def get(self):
        self.write('this endpoint use to auth, data format: {"username": <>, "password": <>}')

    def post(self):
        self.set_header('Content-Type', 'application/json')
        try:
            print self.request.body
            data = json.loads(self.request.body)
        except ValueError as e:
            self.set_status(400)
            return self.write(json.dumps({"message": "username and password are required!"}))

        username = data.get("username", None)
        password = data.get("password", None)

        if username and password:
            session = DBSession()
            try:
                user = session.query(User).filter(User.username == username).one()
            except Exception as e:
                logger.error("query db failed, %s" % e.message)
                user = None
                self.set_status(403)
                self.write(json.dumps({"message": "user %s not exist!" % username}))
            finally:
                session.close()

            if user:
                if hashlib.sha256(password).hexdigest() == user.password:
                    payload = {'id': user.id,
                               'username': username,
                               'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=43200),
                               }
                    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                    response = {'token': token}
                    self.write(response)
                else:
                    self.set_status(403)
                    self.write(json.dumps({"message": 'authentication failed!'}))
        else:
            self.set_status(400)
            self.write(json.dumps({"message": 'username and password are required.'}))

