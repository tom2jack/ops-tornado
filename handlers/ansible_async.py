# -*- coding:utf-8 -*-
from __future__ import unicode_literals

import json
import logging
import os
from tempfile import NamedTemporaryFile
from uuid import uuid4

import yaml
from concurrent.futures import ThreadPoolExecutor
from extra_python_libs.common_tools.my_exceptions import WorkFlowError
from tornado import gen
from tornado.concurrent import run_on_executor
from tornado.web import HTTPError
from tornado.web import RequestHandler
from tornado.websocket import WebSocketHandler

from extra_python_libs.common_tools.my_ansible_api import Ad_Hoc, MyPlaybook, Task
from extra_python_libs.common_tools.utils import Dict, CommonMiXin, gen_keys, save_key_to_file
from model.models import Record, DBSession, SSHKey
from settings import THREAD_POOL_MAX, PLAYBOOK_DIR, SSH_KEY_DIR


logger = logging.getLogger('tornado.app')


class MainHandler(RequestHandler):
    def get(self):
        if self.request.headers.get('auth'):
            self.request.headers.get('auth')
        self.render("test_websocket.html")


class CommandHandler(RequestHandler, CommonMiXin):
    executor = ThreadPoolExecutor(THREAD_POOL_MAX)

    def __init__(self, *args, **kwargs):
        super(CommandHandler, self).__init__(*args, **kwargs)
        self.validate_data = Dict()

    def _validate_json(self):
        try:
            data = json.loads(self.request.body)
        except ValueError as e:
            logger.error("dump input data error: %s" % e.message)
            raise WorkFlowError("the pass data must be json data structure!")
        self.validate_data.data = data

    def _validate_required(self):
        required_field = ['resource', 'command']
        for field in self.validate_data.data:
            if field not in required_field:
                raise WorkFlowError("%s must be required!" % field)

    def validate(self):
        self._validate_json()
        self._validate_required()

    @gen.coroutine
    def post(self):
        self.add_my_header()
        self.validate()
        response = yield self.exec_command(self.validate_data.resource, self.validate_data.command)
        self.write(str(response))
        self.finish()

    @run_on_executor
    def exec_command(self, resource, command):
        """
        use ansible shell module to execute command on inventory.

        Args:
            resource: inventory resource, see Resource Class
            command: which command you want to execute
        Returns:
            AnsibleReuslt: AnsibleResult instance, contain the all ansible return information.
        """
        res = Ad_Hoc(resource)
        result = res.run(command, 'setup')
        return json.dumps(result.result_deal)


class AdHocHandler(RequestHandler):
    executor = ThreadPoolExecutor(THREAD_POOL_MAX)

    @gen.coroutine
    def post(self):
        self.set_header('Content-Type', 'application/json')
        try:
            data = json.loads(self.request.body)
        except ValueError as e:
            raise HTTPError(400, reason=e.message)
        logger.debug("input data: %s" % data)
        resource, module_name, module_arg, complex_args = data.get("resource"), data.get("module_name"), \
                                                          data.get("module_arg"), data.get("complex_args")
        if not(resource and module_name):
            raise HTTPError(400, reason="resource and module_name are required.")

        if not (module_arg or complex_args):
            raise HTTPError(400, reason="module_arg or complex_args are required.")

        if complex_args:
            module_arg = {}

        response = yield self.ad_hoc(resource, module_name, module_arg, complex_args)
        self.write(str(response))
        self.finish()

    @run_on_executor
    def ad_hoc(self, resource, module_name, module_arg, complex_args):
        """
        执行ansible hoc-ad

        Args:
            resource:  ditto
            module_name: ditto
            module_arg: ditto
        """
        res = Ad_Hoc(resource)
        result = res.run(module_arg, complex_args, module_name)
        return json.dumps(result.mcloud_deal)


class SetupHandler(RequestHandler, CommonMiXin):
    executor = ThreadPoolExecutor(THREAD_POOL_MAX)

    def __init__(self, *args, **kwargs):
        super(SetupHandler, self).__init__(*args, **kwargs)
        self.validate_data = Dict()

    def _validate_json(self):
        try:
            data = json.loads(self.request.body)
            self.validate_data.data = data
        except ValueError as e:
            logger.error("dump input data error: %s" % e.message)
            raise WorkFlowError("input data must be json data structure!")

    def _validate_required(self):
        required_field = ['resource']
        for required in required_field:
            if required not in self.validate_data.data:
                raise WorkFlowError("%s must be required!" % required)
        self.validate_data.resource = self.validate_data.data['resource']

    def validate(self):
        try:
            self._validate_json()
            self._validate_required()
        except Exception as e:
            return False, e.message
        return True, None

    @gen.coroutine
    def post(self):
        self.add_my_header()
        status, message = self.validate()
        if status:
            response = yield self.exec_command(self.validate_data.resource)
            code = 200
        else:
            code = 400
            response = message
        self.my_response(code, response)

    @run_on_executor
    def exec_command(self, resource):
        """
        use ansible shell module to execute command on inventory.

        Args:
            resource: inventory resource, see Resource Class
            command: which command you want to execute
        Returns:
            AnsibleReuslt: AnsibleResult instance, contain the all ansible return information.
        """
        res = Ad_Hoc(resource)
        result = res.run('', 'setup')
        return result.result_deal


class SysUserHandler(RequestHandler, CommonMiXin):
    executor = ThreadPoolExecutor(THREAD_POOL_MAX)

    def __init__(self, *args, **kwargs):
        super(SysUserHandler, self).__init__(*args, **kwargs)
        self.validate_data = Dict()
        self.session = DBSession()

    def _validate_json(self):
        try:
            data = json.loads(self.request.body)
            self.validate_data.data = data
        except ValueError as e:
            logger.error("dump input data error: %s" % e.message)
            raise WorkFlowError("input data must be json data structure!")

    def _validate_required(self):
        required_field = ['resource', 'username']
        for required in required_field:
            if required not in self.validate_data.data:
                raise WorkFlowError("%s must be required!" % required)
        self.validate_data.resource = self.validate_data.data['resource']
        self.validate_data.username = self.validate_data.data['username']
        self.validate_data.key_pass = self.validate_data.data.get("key_pass", None)

    def validate(self):
        try:
            self._validate_json()
            self._validate_required()
        except Exception as e:
            return False, e.message
        return True, None

    @gen.coroutine
    def post(self):
        self.add_my_header()
        status, message = self.validate()
        if status:
            response = yield self.add_system_user(self.validate_data.resource,
                                                  self.validate_data.username,
                                                  self.validate_data.key_pass)
            code = 200
        else:
            code = 400
            response = message
        self.my_response(code, response)

    @gen.coroutine
    def put(self):
        self.ImplementError()

    @gen.coroutine
    def get(self):
        self.ImplementError()

    @gen.coroutine
    def delete(self, *args, **kwargs):
        self.add_my_header()
        status, message = self.validate()
        if status:
            response = yield self.del_system_user(self.validate_data.resource,
                                                  self.validate_data.username)
            code = 200
        else:
            code = 400
            response = message
        self.my_response(code, response)

    @run_on_executor
    def add_system_user(self, resource, username, key_password):
        """
        use ansible shell module to execute command on inventory.

        Args:
            resource: inventory resource, see Resource Class
            username: which user you want to add
            key_password: the ssh private key password
        Returns:
            AnsibleReuslt: AnsibleResult instance, contain the all ansible return information.
        """
        task = Task(resource)
        key_dir = os.path.join(SSH_KEY_DIR, uuid4().hex)
        private, public = gen_keys(key_password)
        pri_file, pub_file = save_key_to_file(private, public, key_password, key_dir)
        add_user = task.add_user(username)
        add_key = task.push_key(username, pub_file)

        try:
            ssh_key = SSHKey(username=username,
                             private_key=private,
                             public_key=public,
                             key_password=key_password,
                             cache_dir=key_dir)
            self.session.add(ssh_key)
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            logger.error("save ssh key instance to database failed!, %s" % e.message)
        finally:
            self.session.close()

        result = {"add_user": add_user.result_deal, "add_key": add_key.result_deal}
        return result

    @run_on_executor
    def del_system_user(self, resource, username):
        """
        use ansible shell module to execute command on inventory.

        Args:
            resource: inventory resource, see Resource Class
            username: which user you want to add
        Returns:
            AnsibleReuslt: AnsibleResult instance, contain the all ansible return information.
        """
        task = Task(resource)
        del_user = task.del_user(username)
        return del_user.result_deal


class PlaybookHandler(RequestHandler):
    executor = ThreadPoolExecutor(THREAD_POOL_MAX)

    def __init__(self, *args, **kwargs):
        self.task_id = uuid4().hex
        super(PlaybookHandler, self).__init__(*args, **kwargs)

    @gen.coroutine
    def post(self):
        try:
            data = json.loads(self.request.body)
        except ValueError as e:
            raise HTTPError(400, reason=e.message)
        logger.debug("input data: %s" % data)
        resource, playbook, vars = data.get("resource"), data.get("playbook"), data.get("vars")
        if not(resource and playbook):
            raise HTTPError(400, reason="resource and playbook are required.")
        self.write(self.task_id)
        self.finish()
        response = yield self.run(resource, playbook, vars)
        logger.debug(response)

    @run_on_executor
    def run(self, resource, playbook, variable_dict):
        """
        执行ansible playbook
        Args:
            resource:  ditto
            playbook: ditto
            variable_dict: playbook variable dict
        """

        res = MyPlaybook(resource, playbook, self.task_id, Record)
        result = res.run(variable_dict)
        return {"task_id": self.task_id, "result": result}


class TaskAsyncHandler(RequestHandler):
    executor = ThreadPoolExecutor(THREAD_POOL_MAX)

    def __init__(self, *args, **kwargs):
        self.session = DBSession()
        super(TaskAsyncHandler, self).__init__(*args, **kwargs)

    @gen.coroutine
    def get(self):
        self.set_header('Content-Type', 'application/json')
        req_id = self.get_argument('id')
        if req_id:
            results = yield self.get_data(req_id)
            results
            self.write(json.dumps(results))
        else:
            self.write("id are required!")
        self.finish()

    @run_on_executor
    def get_data(self, req_id):
        """
        执行ansible playbook
        Args:
            resource:  ditto
            playbook: ditto
            variable_dict: playbook variable dict
        """
        results_objs = self.session.query(Record).filter(Record.req == str(req_id)).all()
        results_list = [{'submit_time': obj.submit_time.strftime('"%Y-%m-%d %H:%M:%S'),
                         'states': obj.states,
                         'step': obj.step,
                         'msg': obj.msg} for obj in results_objs
                        ]
        return results_list


class PlaybookWebSocket(WebSocketHandler):
    clients = set()
    tasks = set()

    def __init__(self, *args, **kwargs):
        self.task_id = uuid4().hex
        self.validated_data = Dict()
        self.task_result = {}
        self.cmop = None
        super(PlaybookWebSocket, self).__init__(*args, **kwargs)

    def check_origin(self, origin):
        return True

    def open(self):
        # TODO: auth
        PlaybookWebSocket.clients.add(self)
        logger.debug("WebSocket opened")
        self.stream.set_nodelay(True)

    def on_message(self, message):
        self.validate(message)
        if self.validated_data.status:
            playbook = None
            resource = None
            extra_variables = None
            try:
                self.write_message("==> generate playbook <==")
                playbook = self.gen_playbook()
                resource = self.gen_resource()
                extra_variables = self.validated_data.extra_args
                logger.debug("generate playbook is: %s" % playbook)
                logger.debug("generate inventory is: %s" % resource)
                logger.debug("playbook extra variables is :%s" % extra_variables)
                self.write_message('<span style="color:green">successful</span>')
            except Exception as e:
                if playbook:
                    os.remove(playbook)
                self.write_message('<span style="color:red">generate playbook failed!, %s</span>' % e.message)

            if playbook and resource:
                try:
                    self.write_message('<span style="color:green">successful</span>')
                except Exception as e:
                    self.write_message('<span style="color:red">acquire eip failed!, %s</span>' % e.message)

                self.write_message("==> starting execute playbook <==")
                try:
                    with ThreadPoolExecutor(max_workers=THREAD_POOL_MAX) as executor:
                        f = executor.submit(self.run, resource, playbook, extra_variables)
                        result = f.result()

                        # pop task result to deal with
                        for host, stats in result.iteritems():
                            self.task_result[host] = stats.pop("result")

                        self.write_message(result)
                        logger.debug(result)
                except Exception as e:
                    self.write_message('<span style="color:red">execute playbook failed, %s</span>' % e.message)
                finally:
                    try:
                        self.write_message('<span style="color:green">successful</span>')
                        os.remove(playbook)
                    except Exception as e:
                        self.write_message('<span style="color:red">%s</span>' % e.message)

    def _validate(self, message):
        """
        validate the input data are validated.

        :param message: the required message. the message date structure is :
        playbook: [{"hosts": <hostname>, "role": <rolename>}, {"hosts": <hostname>, "role": <rolename>}]
        extra_args: {"variable1": <a>, "variable2": <b>}
        inventory: [{"ecs_code": testCode, "ssh_port": 22, "ssh_user": "test", "ssh_pass": "test"}]

        :return: None, but set the validated_data attribute.
        """
        # 检查是否是正确的json格式的数据
        try:
            data = json.loads(json.loads(message))
            self.validated_data.status = True
            logger.debug("websocket input data: %s" % data)
        except ValueError as e:
            logger.warning("decode json failed! :%s" % e.message)
            self.validated_data.status = False
            raise WorkFlowError("the message you require must be json string!")

        # 检查playbook传人的数据是否合法
        try:
            self.validated_data.playbook = data['playbook']
        except Exception as e:
            message = "the field playbook are required!"
            logger.warning(message + e.message)
            raise WorkFlowError(message)

        if not isinstance(self.validated_data.playbook, list):
            raise WorkFlowError("the field playbook must be a array object.")

        if not self.validated_data.playbook:
            raise WorkFlowError("the field playbook has no data")

        playbook_keys = self.validated_data.playbook[0].keys()
        playbook_required_key = ["hosts", "roles"]
        for key in playbook_required_key:
            if key not in playbook_keys:
                raise WorkFlowError("%s are required!" % key)

        # 检查inventory传人的数据是否合法
        try:
            self.validated_data.inventory = data['inventory']
        except Exception as e:
            raise WorkFlowError("the field inventory are required!")

        if not isinstance(self.validated_data.inventory, list):
            raise WorkFlowError("the inventory must be an array!")

        if not self.validated_data.inventory:
            raise WorkFlowError("the inventory has no ecs!")

        if not isinstance(self.validated_data.inventory[0], dict):
            raise WorkFlowError("the inventory ecs element must be an object!")

        inventory_keys = self.validated_data.inventory[0].keys()
        inventory_required_key = ["ecs_code", "username", "password", "port"]
        for key in inventory_required_key:
            if key not in inventory_keys:
                raise WorkFlowError("%s are required!" % key)

        # extra_args是非必须参数
        self.validated_data.extra_args = data.get("variables", None)

    def validate(self, message):
        try:
            self._validate(message)
            self.validated_data.status = True
        except WorkFlowError as e:
            self.validated_data.status = False
            self.write_message("validated failed! %s" % e.message)

    def gen_playbook(self):
        """
        use the validated_data generate a playbook with random name under the playbook directory

        :return: <str> absolute playbook path
        """
        try:
            yml = yaml.safe_dump(self.validated_data.playbook)
            playbook = NamedTemporaryFile(dir=PLAYBOOK_DIR, delete=False)
            playbook.write(yml)
            playbook.close()
            return playbook.name
        except Exception as e:
            self.write_message("validated failed! %s" % e.message)
            return None

    def gen_resource(self):
        """
        use to generate the resource data structure. if this is a MySQL Galera Cluster, will add
        variables to galera_cluster_nodes.

        :return: resource dict
        """
        count = 0
        try:

            variables = self.validated_data.extra_args

            # get default ip to mysql galera cluster configure.
            if "galera_cluster_name" in variables.keys():
                variables["galera_cluster_nodes"] = []
                for host in self.validated_data.inventory:
                    count += 1
                    ecs_code = host['ecs_code']
                    default_ip = self.cmop.vm.default_ip(ecs_code)
                    default_network = self.cmop.vm.default_network_card(ecs_code)
                    host['hostname'] = default_ip
                    host['default_network'] = default_network
                    variables["galera_cluster_nodes"].append({"ip": default_ip, "name": "node"+str(count)})
            return self.validated_data.inventory
        except Exception as e:
            logger.error('Generate playbook resource failed!, %s' % e.message)
            return None

    def send_web(self, msg, color):
        try:
            str_msg = msg.decode('utf-8')
        except UnicodeEncodeError as e:
            str_msg = msg
        if color:
            msgs = "<span style=\"color:" + color + "\">" + str_msg + "</span>"
        else:
            msgs = "<span>" + str_msg + "</span>"
        logger.debug("send web: %s" % msgs)
        self.write_message(msgs)

    def on_close(self):
        PlaybookWebSocket.clients.remove(self)
        logger.debug('WebSocket closed')

    def run(self, resource, playbook, variable_dict):
        """
        执行ansible playbook
        Args:
            resource:  ditto
            playbook: ditto
            variable_dict: playbook variable dict
        """

        res = MyPlaybook(resource, playbook, self.task_id, Record)
        res.send_web = self.send_web
        result = res.run(variable_dict)
        logger.debug("WebSocket run command: %s" % result)
        return result


class SSHPrivateKey(RequestHandler, CommonMiXin):
    executor = ThreadPoolExecutor(THREAD_POOL_MAX)

    def __init__(self, *args, **kwargs):
        self.session = DBSession()
        super(SSHPrivateKey, self).__init__(*args, **kwargs)

    @gen.coroutine
    def get(self, id):
        """
        download ssh private key
        """
        try:
            try:
                ssh_key = self.session.query(SSHKey).get(id)
                private_file = os.path.join(ssh_key.cache_dir, 'id_rsa')
                username = ssh_key.username
            except Exception as e:
                raise WorkFlowError("query database error, %s" % e.message)

            self.set_header('Content-Type', 'application/force-download')
            self.set_header('Content-Disposition', 'attachment; filename=%s-%s' % (username, 'id_rsa'))
            with open(private_file, "rb") as f:
                try:
                    while True:
                        _buffer = f.read(4096)
                        if _buffer:
                            self.write(_buffer)
                        else:
                            f.close()
                            self.finish()
                            return
                except Exception as e:
                    raise HTTPError(500, reason='read file failed: %s' % e.message)
        except Exception as e:
            logger.error(e.message)
            self.my_response(400, e.message)



