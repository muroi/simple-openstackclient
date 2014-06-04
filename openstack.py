# -*- coding: utf-8 -*-

import urllib
import urllib2
import json
import requests

debug = False

class BaseService:
    def __init__(self, tenant, name, passwd):
        self.name = name
        self.passwd = passwd
        self.tenant = tenant


class HttpRequest:
    def __init__(self, url, body={}, headers={}):
        self.url = url
        self.body = body
        self.headers = headers

    def call(self, method="GET"):
        if method == "GET":
            req = requests.get(self.url, headers=self.headers)
        elif method == "POST":
            req = requests.post(self.url, data=json.dumps(self.body), headers=self.headers)
        elif method == "DELETE":
            req = requests.delete(self.url, headers=self.headers)
        else:
            raise Exception("call not supported method %s" % method)

        if debug is True:
            print 'method' % method
            print 'url: %s' % self.url
            print 'body: %s' % self.body
            print 'headers: %s' % self.header

        return req.content

    
class HeatService(BaseService):
    def __init__(self, tenant, name, passwd):
        BaseService.__init__(self, tenant, name, passwd)

    def set_keystone(self, ks):
        self.keystone = ks
    
    def stack_create(self, s_name, tempalte, env={}, param={}):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        body = {
            "stack_name": s_name,
            "template": template,
            }

        request = HttpRequest(url, body, header)
        resp = json.loads(request.call("POST"))

        return resp


    def stack_list(self, name="", status=""):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call())
        
        return resp

    
    def stack_show(self, stack_name, stack_id=None):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        if stack_id is None:
            stack_id = self._fetch_stack_id(stack_name)

        url = '/'.join([url, stack_name, stack_id])

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call())

        return resp


    def stack_delete(self, stack_name, stack_id=None):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()
        
        if stack_id is None:
            stack_id = self._fetch_stack_id(stack_name)

        url = '/'.join([url, stack_name, stack_id])

        request = HttpRequest(url, headers=header)
        resp = request.call(method='DELETE')

        return resp

    def _fetch_stack_id(self, stack_name):
        s_list = self.stack_list()

        for stack in s_list['stacks']:
            stack['stack_name'] == stack_name
            return stack['id']

        raise Exception('no stack named: %s' % stack_name)

    def _generate_base_url(self):
        heat_endpoint = self.keystone.fetch_endpoint(endpoint_type="orchestration")
        url = heat_endpoint[0]['endpoints'][0]['publicURL'] + '/stacks'
        
        return url


    def _generate_common_headers(self, token=None):
        header = {
            "X-Auth-User": self.name,
            "X-Auth-Key": self.passwd,
            "Content-type": "application/json",
            }

        if token is not None:
            header['X-Auth-Token'] = token
        
        return header

class KeystoneService(BaseService):
    def __init__(self, tenant, name, passwd):
        BaseService.__init__(self, tenant, name, passwd)


    def set_keystone_endpoint(self, url):
        self.keystone_url = url


    def generate_token_id(self):
        response = self.token_get()
        return response["access"]["token"]["id"]


    def fetch_endpoint(self, endpoint_name="", endpoint_type=""):
        if endpoint_name == "" and endpoint_type == "":
            raise Exception('specify at least endpoint_name')
        
        token_response = self.token_get()
        catalog = token_response["access"]["serviceCatalog"]
        
        if endpoint_name != "":
            endpoint = [e for e in catalog if e["name"] == endpoint_name]
                        
        elif endpoint_type != "":
            endpoint = [e for e in catalog if e["type"] == endpoint_type]
                        
        return endpoint

        
    def token_get(self):
        url = self.keystone_url + '/tokens'

        header = {
            "Content-type": "application/json"
            }

        data = {
            "auth": {
                "tenantName": self.tenant,
                "passwordCredentials": {
                    "username": self.name,
                    "password": self.passwd
                    }
                }
            }

        request = HttpRequest(url, data, header)
        resp = json.loads(request.call("POST"))

        return resp
