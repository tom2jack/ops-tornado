#!/usr/bin/env python
import environment
import tornado.httpserver
import tornado.ioloop
import tornado.web
from tornado.options import options

from routers.urls import url_patterns
from settings import settings
from model.models import init_db


class TornadoBoilerplate(tornado.web.Application):
    def __init__(self):
        tornado.web.Application.__init__(self, url_patterns, **settings)
        init_db()


def main():
    app = TornadoBoilerplate()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()

