from handlers.ansible_async import *
from handlers.auth import AuthHandler


url_patterns = [

    (r"/token", AuthHandler),
    (r"/", MainHandler),
    (r"/command", CommandHandler),
    (r"/ad_hoc", AdHocHandler),
    (r"/get_info", SetupHandler),
    (r"/system_user", SysUserHandler),
    (r"/private_key/download/(\d+)", SSHPrivateKey),
    (r"/playbook", PlaybookHandler),
    (r"/websocket", PlaybookWebSocket),
    (r"/task", TaskAsyncHandler),
]
