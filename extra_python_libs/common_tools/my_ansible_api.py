# -*- coding: utf-8 -*-
"""
Purpose: This module is for custom ansible api for tornado.
Author: Yu Maojun
Date: 2016-03-20
Version: 0.0.1
"""


from __future__ import unicode_literals
from ansible.inventory import Inventory
from ansible.inventory.group import Group
from ansible.inventory.host import Host
from ansible.runner import Runner
from ansible.playbook import PlayBook
from ansible import callbacks, utils
from passlib.hash import sha512_crypt
from ansible.callbacks import PlaybookCallbacks, PlaybookRunnerCallbacks, AggregateStats

from model.models import DBSession

import os
import json
import logging


import ansible.constants as C
logger = logging.getLogger('tornado.app')

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOK_DIR = os.path.join(ROOT_DIR, 'ansible_playbooks')


def config_ansible():
    C.HOST_KEY_CHECKING = False
    C.DEFAULT_MODULE_PATH = os.path.join(ROOT_DIR, 'extra_ansible_modules')


class AnsibleError(StandardError):
    """
    the base AnsibleError which contains all error_message message.

    Attributes:
        message: <str> the main error_message message
        kwargs: <dict> the other message data
    """
    def __init__(self, message='', **kwargs):
        super(AnsibleError, self).__init__(message)
        self.message = message
        for key, value in kwargs.items():
            setattr(self, key, value)


class CommandError(AnsibleError):
    """
    the ansible command execute error_message.
    """
    def __init__(self, message=''):
        super(CommandError, self).__init__(message)


class ResourceBase(object):
    """
    gen_inventory methods.

    Attributes:
        resource: the inventory's resource. format:
                    {
                        "group1": {
                            "hosts": [{"hostname": "10.10.10.10", "port": "22", "username": "test", "password": "mypass"}, ...],
                            "vars": {"var1": value1, "var2": value2, ...}
                        }
                    }
                  if your pass a list, the list will add the default group(default_group)
                    [{"hostname": "10.10.10.10", "port": "22", "username": "test", "password": "mypass"}, ...]
        inventory: ansible inventory object use gen_inventory to generate.
    Methods:
        gen_inventory: generate a ansible inventory object.
    """

    def __init__(self, resource):
        self.inventory = Inventory(host_list=[])
        self.resource = resource
        self.gen_inventory()

    @staticmethod
    def add_group_vars(group, group_vars=None):
        """
        if group_vars exists then, add group variable to group

        Args:
            group: <ansible group object> ansible group object
            group_vars: <dict> group variables
        """
        assert isinstance(group, Group), "the group must be an ansible group object."

        if group_vars:
            for key, value in group_vars.iteritems():
                group.set_variable(key, value)

    @staticmethod
    def gen_hosts(hosts=None):
        """
        if host_vars exists then, generate hosts

        Args:
             hosts: <list> [<host variable dict>, <host variable dict>, ...]
        Returns:
             host_objs: <list> [<host object>, <host object>, ...]
        """
        assert isinstance(hosts, list), "the hosts must be a list"
        host_objs = []
        if hosts:
            for host in hosts:
                hostname = host.get("hostname")
                hostip = host.get('ip', hostname)
                hostport = host.get("port")
                username = host.get("username")
                password = host.get("password")
                ssh_key = host.get("ssh_key")
                sudo = host.get("sudo")

                my_host = Host(name=hostname, port=hostport)
                my_host.set_variable('ansible_ssh_host', hostip)
                my_host.set_variable('ansible_ssh_port', hostport)
                my_host.set_variable('ansible_ssh_user', username)

                if password:
                    my_host.set_variable('ansible_ssh_pass', password)
                if ssh_key:
                    my_host.set_variable('ansible_ssh_private_key_file', ssh_key)
                if sudo:
                    my_host.set_variable("ansible_sudo_pass", password)
                    my_host.set_variable("ansible_sudo", "yes")

                # set other variables
                for key, value in host.iteritems():
                    if key not in ["hostname", "port", "username", "password", "ip", "ssh_key"]:
                        my_host.set_variable(key, value)
                host_objs.append(my_host)
        return host_objs

    def my_add_group(self, hosts_vars, group_name, group_vars=None):
        """
        add hosts to group. use to generate a inventory.

        Args:
            hosts_vars: the hosts variables
            group_name: group name
            group_vars: group variables
        """
        my_group = Group(name=group_name)
        self.add_group_vars(my_group, group_vars)
        for host in self.gen_hosts(hosts_vars):
            my_group.add_host(host)
        self.inventory.add_group(my_group)

    def gen_inventory(self):
        """
        add hosts to an inventory.
        """
        if isinstance(self.resource, list):
            self.my_add_group(self.resource, 'default_group')
        elif isinstance(self.resource, dict):
            for group_name, hosts_vars in self.resource.iteritems():
                self.my_add_group(hosts_vars.get("hosts"), group_name, hosts_vars.get("vars"))


class Ad_Hoc(ResourceBase):
    """
    execute ansible ad-hoc mode in inventory.

    Args:
        resource:　the inventory resource, the resource format see MyRunner on top of this module
        command: which command your want to run in this resource
    Attributes:
        results_raw: the raw data returned after ansible run.
    """
    def __init__(self, resource):
        super(Ad_Hoc, self).__init__(resource)

    def run(self, module_arg, module_name="shell", complex_args=None, timeout=10, forks=10, pattern='*'):
        """
        run command from andible ad-hoc.

        Args:
            module_arg: ansible module argument
            complex_args: complex structure argument
            module_name: which module want to use, default use shell
            timeout: set runner api
            forks: see runner api
            pattern: set runner api
        """
        hoc = Runner(module_name=module_name,
                     module_args=module_arg,
                     complex_args=complex_args,
                     timeout=timeout,
                     inventory=self.inventory,
                     pattern=pattern,
                     forks=forks,
                     module_path=C.DEFAULT_MODULE_PATH,
                     )
        return_data = hoc.run()
        logger.info(return_data)
        return AnsibleResult(return_data)


class Task(Ad_Hoc):
    """
    execute ansible module.
    """
    def push_key(self, user, key_path):
        """
        push the ssh authorized key to target.
        """
        module_args = 'user="%s" key="{{ lookup("file", "%s") }}" state=present' % (user, key_path)
        return_data = self.run(module_args, "authorized_key")
        return return_data

    def del_key(self, user, key_path):
        """
        push the ssh authorized key to target.
        """
        module_args = 'user="%s" key="{{ lookup("file", "%s") }}" state="absent"' % (user, key_path)
        return_data = self.run(module_args, "authorized_key")
        return return_data

    def add_user(self, username, password=None):
        """
        add a host user.
        """

        if password:
            encrypt_pass = sha512_crypt.encrypt(password)
            module_args = 'name=%s shell=/bin/bash password=%s generate_ssh_key=yes' % (username, encrypt_pass)
        else:
            module_args = 'name=%s shell=/bin/bash generate_ssh_key=yes' % username
        return_data = self.run(module_args, "user")
        return return_data

    def del_user(self, username):
        """
        delete a host user.
        """
        module_args = 'name=%s state=absent remove=yes move_home=yes force=yes' % username
        return_data = self.run(module_args, "user")
        return return_data


class AnsibleResult(object):
    """
    container ansible return result.

    Attributes:
        result_raw: ansible return raw data
    """
    def __init__(self, raw_data):
        self.result_raw = raw_data

    @property
    def dark(self):
        """
        return the failed dark message.

        Returns:
            failed: <dict> eg:{'failed': {'localhost': ''}}
        """
        failed = {}
        dark = self.result_raw.get("dark")
        if dark:
            for host, info in dark.items():
                failed[host] = info.get('msg')
        return failed

    @property
    def contacted(self):
        """
        return the contacted message.

        Returns:
            contacted: <dict> {'failed': {'host1': ''}, 'ok': {'host2': ''}}
        """
        result = {'failed': {}, 'ok': {}}
        contacted = self.result_raw.get("contacted")
        if contacted:
            for host, info in contacted.items():
                if info.get('invocation').get('module_name') in ['raw', 'shell', 'command', 'script']:
                    if info.get('rc') == 0:
                        result['ok'][host] = info.get('stdout') + info.get('stderr')
                    else:
                        result['failed'][host] = info.get('stdout') + info.get('stderr')
                elif info.get('invocation').get('module_name') == 'setup':
                        result['ok'] = self.setup_filter(info.get('ansible_facts'))
                else:
                    if info.get('failed'):
                        result['failed'][host] = info.get('msg')
                    else:
                        result['ok'][host] = info.get('result')
        return result

    @property
    def result_deal(self):
        """
        deal the ansible return result.

        Returns:
            results: <dict> eg: {'failed': {'host1': ''}, 'ok': {'host2': ''}}
        """
        results = {'failed': {}, 'ok': {}}
        if self.dark:
            results['failed'].update(**self.dark)
        if self.contacted:
            results['failed'].update(**self.contacted['failed'])
            results['ok'].update(**self.contacted['ok'])
        return results

    @staticmethod
    def setup_filter(fact):
        result = {}
        disk_need = {}
        disk_all = fact.get("ansible_devices")
        if disk_all:
            for disk_name, disk_info in disk_all.iteritems():
                if disk_name.startswith('sd') or disk_name.startswith('hd') or disk_name.startswith('vd') or disk_name.startswith('xvd'):
                    disk_size = disk_info.get("size", '')
                    if 'M' in disk_size:
                        disk_format = round(float(disk_size[:-2]) / 1000, 0)
                    elif 'T' in disk_size:
                        disk_format = round(float(disk_size[:-2]) * 1000, 0)
                    else:
                        disk_format = float(disk_size[:-2])
                    disk_need[disk_name] = disk_format
        all_ip = fact.get("ansible_all_ipv4_addresses")
        default_ip = fact.get("ansible_all_ipv4_addresses")
        other_ip_list = all_ip.remove(default_ip) if default_ip in all_ip else []
        other_ip = ','.join(other_ip_list) if other_ip_list else ''
        mac = fact.get("ansible_default_ipv4").get("macaddress")
        brand = fact.get("ansible_product_name")
        try:
            cpu_type = fact.get("ansible_processor")[1]
        except IndexError:
            cpu_type = ' '.join(fact.get("ansible_processor")[0].split(' ')[:6])

        memory = fact.get("ansible_memtotal_mb")
        try:
            memory_format = int(round((int(memory) / 1000), 0))
        except Exception:
            memory_format = memory
        disk = disk_need
        system_type = fact.get("ansible_distribution")
        if system_type.lower() == "freebsd":
            system_version = fact.get("ansible_distribution_release")
            cpu_cores = fact.get("ansible_processor_count")
        else:
            system_version = fact.get("ansible_distribution_version")
            cpu_cores = fact.get("ansible_processor_vcpus")
        cpu = cpu_type + ' * ' + unicode(cpu_cores)
        system_arch = fact.get("ansible_architecture")
        sn = fact.get("ansible_product_serial")
        result = {"other_ip": other_ip,
                  "mac": mac,
                  "cpu": cpu,
                  "memory_format": memory_format,
                  "disk": disk,
                  "sn": sn,
                  "system_type": system_type,
                  "system_version": system_version,
                  "brand": brand,
                  "system_arch": system_arch,
                  "default_ip": default_ip
                  }
        return result

    def __unicode__(self):
        return "%s" % self.result_raw

    def __str__(self):
        return self.__unicode__()


class CustomAggregateStats(AggregateStats):
    """
    Holds stats about per-host activity during playbook runs.
    Attribute:
        task_result: {'task_step': <int>, 'task_description': <str>, 'task_result': {...}}
                     use to hold the task result
    """
    def __init__(self, task_result):
        super(CustomAggregateStats, self).__init__()
        self.results = task_result
        self.count = 0

    def compute(self, runner_results, setup=False, poll=False, ignore_errors=False):
        """
        Walk through all results and increment stats.
        """
        super(CustomAggregateStats, self).compute(runner_results, setup, poll,
                                                  ignore_errors)
        # for (host, value) in runner_results.get('contacted', {}).iteritems():
        #     if value.get('invocation', {}).get('module_name', None) == 'setup':
        #         value['ansible_facts'] = {"message": "the failed truncate by jumpserver ops platform"}

        self.count += 1
        self.results[-1]['task_step'] = self.count
        self.results[-1]['task_result'] = runner_results
        return runner_results

    def summarize(self, host):
        """
        Return information about a particular host
        """
        summarized_info = super(CustomAggregateStats, self).summarize(host)

        # Adding the info I need
        summarized_info['result'] = self.results

        return summarized_info


class CustomePlaybookCallbacks(PlaybookCallbacks):

    def __init__(self, verbose=False, task_results=[]):
        self.task_results = task_results
        super(CustomePlaybookCallbacks, self).__init__(verbose)

    def on_task_start(self, name, is_conditional):
        self.task_results.append({'task_step': None, 'task_description': name, 'task_result': None})
        super(CustomePlaybookCallbacks, self).on_task_start(name, is_conditional)

    def on_setup(self):
        self.task_results.append({'task_step': None, 'task_description': 'GATHERING FACTS', 'task_result': None})
        super(CustomePlaybookCallbacks, self).on_setup()


class MyPlaybook(ResourceBase):
    """
    this is my playbook object for execute playbook.
    Attributes:
        resource: resource dict ,see ResourceBase class
        playbook_path: relational playbook path, the default playbook directory is: <PLAYBOOK_DIR>
        req: required id
        model: sqlalchemy data model
        ws_function: web socket write message function
    """
    def __init__(self, resource, playbook_path, req_id, model):
        super(MyPlaybook, self).__init__(resource)
        self.results_raw = None
        self.playbook_path = playbook_path
        self.req = req_id
        self.model = model
        self.count = 0
        self.session = DBSession()

    def save(self, msg):
        if isinstance(msg, dict):
            msg = json.dumps(msg)
            states = 'SUCCESS'
        else:
            states = 'STARTED'
            try:
                msg = msg.decode('utf-8')
            except UnicodeEncodeError:
                msg = msg
        record = self.model(step=self.count, req=self.req, msg=msg, states=states)
        self.session.add(record)
        self.session.commit()
        self.session.close()

    def send_web(self, msg, color):
        pass

    def display(self, msg, color=None, stderr=False, screen_only=False, log_only=False, runner=None):
        self.count += 1
        self.save(msg)
        self.send_web(msg, color)

    def run(self, extra_vars=None):
        """
        run ansible playbook, only surport relational path.
        Args:
            extra_vars: playbook extra variables.
        """
        task_results = []
        stats = CustomAggregateStats(task_results)
        callbacks.display = self.display
        playbook_cb = CustomePlaybookCallbacks(verbose=utils.VERBOSITY, task_results=task_results)
        runner_cb = PlaybookRunnerCallbacks(stats=stats, verbose=utils.VERBOSITY)
        playbook_path = os.path.join(PLAYBOOK_DIR, self.playbook_path)

        pb = PlayBook(
            playbook=playbook_path,
            stats=stats,
            callbacks=playbook_cb,
            runner_callbacks=runner_cb,
            inventory=self.inventory,
            extra_vars=extra_vars,
            module_path=C.DEFAULT_MODULE_PATH,
            check=False)

        self.results_raw = pb.run()
        self.count += 1
        self.save(self.results_raw)
        return self.results_raw


if __name__ == "__main__":
    resource = [{"hostname": "192.168.220.131", "port": "22", "username": "root", "password": "123456"}]
    cmd = Ad_Hoc(resource)
    result = cmd.run('ip a', 'command')
    print(result.result_deal)
