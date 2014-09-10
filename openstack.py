#!/usr/bin/python
# -*- coding: utf-8 -*-

import urllib
import urllib2
import json
import requests

debug = True

class BaseService:
    def __init__(self, tenant, name, passwd):
        self.name = name
        self.passwd = passwd
        self.tenant = tenant

    def set_keystone(self, ks):
        self.keystone = ks


class HttpRequest:
    def __init__(self, url, body={}, headers={}):
        self.url = url
        self.body = body
        self.headers = headers

    def call(self, method="GET"):
        if method == "GET":
            res = requests.get(self.url, headers=self.headers)
        elif method == "POST":
            res = requests.post(self.url, data=json.dumps(self.body),
                                headers=self.headers)
        elif method == "DELETE":
            res = requests.delete(self.url, headers=self.headers)
        elif method == "PUT":
            res = requests.put(self.url, data=json.dumps(self.body),
                               headers=self.headers)
        elif method == "PATCH":
            res = requests.patch(self.url, data=json.dumps(self.body),
                               headers=self.headers)
        elif method == "HEAD":
            res = requests.head(self.url, headers=self.headers)
        else:
            raise Exception("call not supported method %s" % method)

        if debug is True:
            print 'method: %s' % method
            print 'url: %s' % self.url
            print 'body: %s' % self.body
            print 'headers: %s' % self.headers
            print 'response headers: %s' % res.headers
            print 'response body: %s' % res.content

        return res


class NovaService(BaseService):
    def __init__(self, tenant, name, passwd):
        BaseService.__init__(self, tenant, name, passwd)

    def _generate_base_url(self, url_type='publicURL'):
        '''
        return nova endpoint url
        '''
        heat_endpoint = self.keystone.fetch_endpoint(endpoint_type="compute")
        url = heat_endpoint[0]['endpoints'][0][url_type]
        
        return url

    def _generate_common_headers(self, token):
        header = {
            "Content-type": "application/json",
            'X-Auth-Token': token
            }
        
        return header

    def create_server_with_volume(self, name, flavor, block_device, image=None):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url() + '/servers'

        body = {
            'server': {
                'name'                 : name,
                'flavorRef'            : flavor,
                'block_device_mapping' : block_device
                }
            }

        if image is not None:
            body['server']['imageRef'] = image

        request = HttpRequest(url, body, header)
        resp = json.loads(request.call("POST").content)

        return resp
            
    def detach_volume(self, server_id, volume_id):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url() + '/servers' + server_id +\
            'os-volume_attachments' + volume_id
            
        request = HttpRequest(url, headers=header)
        resp = request.call(method='DELETE').content

        return resp


class CinderService(BaseService):
    def __init__(self, tenant, name, passwd):
        BaseService.__init__(self, tenant, name, passwd)

    def _generate_base_url(self, url_type='publicURL'):
        '''
        return cinder endpoint url
        '''
        heat_endpoint = self.keystone.fetch_endpoint(endpoint_type="volumev2")
        url = heat_endpoint[0]['endpoints'][0][url_type]
        
        return url

    def _generate_common_headers(self, token):
        header = {
            "Content-type": "application/json",
            'X-Auth-Token': token
            }
        
        return header

    def create_volume(self, size, display_name=None, bootable=False, image_ref=None):
        '''
        create a new volume
        '''
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url() + '/volumes'

        body = {
            'volume': {
                'size': size,
                }
            }

        if display_name is not None:
            body['volume']['display_name'] = display_name

        if bootable is True:
            body['volume']['bootable'] = True

        if image_ref is not None:
            body['volume']['imageRef'] = image_ref

        request = HttpRequest(url, body, header)
        resp = json.loads(request.call("POST").content)

        return resp

    def show_volume(self, volume_id):
        '''show a volume detail'''
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url() + '/volumes/' + volume_id

        request = HttpRequest(url, headers=header)
        resp = request.call(method='GET').content

        return resp
        
    def delete_volume(self, volume_id):
        '''
        delete a volume
        '''
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url() + '/volumes/' + volume_id

        request = HttpRequest(url, headers=header)
        resp = request.call(method='DELETE').content

        return resp

    def upload_volume(self, volume_id, container_format,
                      disk_format, image_name, force=False):
        '''
        upload a volume to a image
        '''
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url() + '/volumes/' + volume_id + '/action'

        body = {
            'os-volume_upload_image': {
                'container_format': container_format,
                'disk_format': disk_format,
                'image_name': image_name,
                }
            }

        if force is True:
            body['os-volume_upload_image']['force'] = True

        request = HttpRequest(url, body, header)
        resp = json.loads(request.call("POST").content)

        return resp
        

class HeatService(BaseService):
    def __init__(self, tenant, name, passwd):
        BaseService.__init__(self, tenant, name, passwd)
    
    def stack_create(self, s_name, template, env={}, param={}):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        body = {
            "stack_name": s_name,
            "template": template,
            }

        request = HttpRequest(url, body, header)
        resp = json.loads(request.call("POST").content)

        return resp


    def stack_list(self, name="", status=""):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call().content)
        
        return resp

    
    def stack_show(self, stack_name, stack_id=None):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        if stack_id is None:
            stack_id = self._fetch_stack_id(stack_name)

        url = '/'.join([url, stack_name, stack_id])

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call().content)

        return resp


    def stack_delete(self, stack_name, stack_id=None):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()
        
        if stack_id is None:
            stack_id = self._fetch_stack_id(stack_name)

        url = '/'.join([url, stack_name, stack_id])

        request = HttpRequest(url, headers=header)
        resp = request.call(method='DELETE').content

        return resp

    def stack_find(self, stack_name):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        url = '/'.join([url, stack_name])

        request = HttpRequest(url, headers=header)
        resp = request.call().content

        return resp


    def stack_update(self, s_name, template, env={}, param={}):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        stack_id = self._fetch_stack_id(s_name)

        url = '/'.join([url, s_name, stack_id])

        body = {
            "template": template,
            }

        request = HttpRequest(url, body, header).content
        resp = request.call("PUT")

        return resp

    
    def stack_adopt(self, stack_name, template, resource_data):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        body = {
            "stack_name": stack_name,
            "template": template,
            "adopt_stack_data": resource_data,
            }
        
        request = HttpRequest(url, body, header)
        resp = json.loads(request.call("POST").content)

        return resp

    def stack_abandon(self, stack_name, preview=False):
        token = self.keystone.generate_token_id()
        header = self._generate_common_headers(token)
        url = self._generate_base_url()

        stack_id = self._fetch_stack_id(stack_name)

        url = '/'.join([url, stack_name, stack_id, 'abandon'])

        request = HttpRequest(url, headers=header)
        if preview is True:
            resp = request.call().content
        else:
            resp = request.call("DELETE").content

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

class KeystoneService_V3(BaseService):
    def __init__(self, tenant, name, passwd):
        BaseService.__init__(self, tenant, name, passwd)


    def set_keystone_endpoint(self, url):
        self.keystone_url = url


    def token_get(self):
        url = self.keystone_url + 'auth/tokens'

        header = {
            "Content-type": "application/json"
            }

        data = {
            "auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "id"      : self.name,
                            "password": self.passwd
                        }
                    }
                 }
             }
         }

        request = HttpRequest(url, data, header)
        resp = request.call("POST")

        return resp


    def revoke_token(self, token):
        url = self.keystone_url + 'auth/tokens'
        header = self._generate_common_headers()
        header["X-Auth-Token"] = self.generate_token_id()
        header["X-Subject-Token"] = token

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call("DELETE").content)

        return resp
        

    def generate_token_id(self):
        response = self.token_get()
        return response.headers["x-subject-token"]


    def create_domain(self, name):
        url = self.keystone_url + 'domains'
        
        header = self._generate_common_headers()
        header["X-Auth-Token"] = self.generate_token_id()

        data = {
            "domain": {
                "name": name,
                "enabled": True,
                }
            }

        request = HttpRequest(url, data, header)
        resp = json.loads(request.call('POST').content)

        return resp


    def update_domain(self, domain_id, data):
        url = self.keystone_url + 'domains/' + domain_id
        
        header = self._generate_common_headers()
        header["X-Auth-Token"] = self.generate_token_id()

        request = HttpRequest(url, data, header)
        resp = json.loads(request.call('PATCH').content)

        return resp


    def list_domain(self):
        url = self.keystone_url + 'domains'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def delete_domain(self, domain):
        url = self.keystone_url + 'domains/' + domain
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('DELETE').content)

        return resp


    def create_project(self, name, domain):
        url = self.keystone_url + 'projects'
        
        header = self._generate_common_headers()
        header["X-Auth-Token"] = self.generate_token_id()
        
        data = {
            "project": {
                "name": name,
                "domain_id": domain,
                "enabled": True,
                }
            }

        request = HttpRequest(url, data, header)
        resp = json.loads(request.call('POST').content)

        return resp

        
    def list_project(self):
        url = self.keystone_url + 'projects'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def delete_project(self, project):
        url = self.keystone_url + 'projects/' + project
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('DELETE').content)

        return resp


    def create_user(self, name, password, domain=None):
        url = self.keystone_url + 'users'
        
        header = self._generate_common_headers()
        header["X-Auth-Token"] = self.generate_token_id()
        
        data = {
            "user": {
                "name": name,
                "password": password,
                "enabled": True,
                }
            }

        if domain is not None:
            data['user']['domain_id'] = domain

        request = HttpRequest(url, data, header)
        resp = json.loads(request.call('POST').content)

        return resp


    def list_user(self):
        url = self.keystone_url + 'users'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def list_projects_of_user(self, user):
        url = self.keystone_url + 'users/' + user + '/projects'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def list_roles_of_user(self, user):
        url = self.keystone_url + 'users/' + user + '/roles'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def delete_user(self, user):
        url = self.keystone_url + 'users/' + user
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('DELETE').content)

        return resp


    def create_user_group(self, name, domain):
        url = self.keystone_url + 'groups'
        
        header = self._generate_common_headers()
        header["X-Auth-Token"] = self.generate_token_id()
        
        data = {
            "group": {
                "name"      : name,
                "domain_id" : domain
                }
            }

        request = HttpRequest(url, data, header)
        resp = json.loads(request.call('POST').content)

        return resp


    def add_user_to_group(self, group, user):
        url = self.keystone_url + 'groups/' + group + '/'
        url = url + 'users/' + user + '/'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('PUT').content)

        return resp
    

    def list_group(self):
        url = self.keystone_url + 'groups/'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp

        
    def list_users_in_group(self, group):
        url = self.keystone_url + 'groups/' + group + '/users'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp

        
    def delete_group(self, group):
        url = self.keystone_url + 'groups/' + group
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('DELETE').content)

        return resp


    def grant_role_in_project(self, project, role, user):
        url = self.keystone_url + 'projects/' + project + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/' + role + '/'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('PUT').content)

        return resp


    def list_roles_for_project(self, project, user):
        url = self.keystone_url + 'projects/' + project + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def grant_role_in_domain(self, domain, role, user):
        url = self.keystone_url + 'domains/' + domain + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/' + role + '/'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('PUT').content)

        return resp


    def list_roles_for_domain(self, domain, user):
        url = self.keystone_url + 'domains/' + domain + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()

        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def list_roles(self):
        url = self.keystone_url + 'roles'
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def role_assinment(self, user):
        url = self.keystone_url + 'role_assignments?user.id=' + user
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp
        

    def list_inherit_user(self, domain, user):
        url = self.keystone_url + 'OS-INHERIT/'
        url = url + 'domains/' + domain + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/'
        url = url + 'inherited_to_projects'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('GET').content)

        return resp


    def grant_inherit_role(self, domain, user, role):
        url = self.keystone_url + 'OS-INHERIT/'
        url = url + 'domains/' + domain + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/' + role + '/'
        url = url + 'inherited_to_projects'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('PUT').content)

        return resp


    def validate_inherit_role(self, domain, user, role):
        url = self.keystone_url + 'OS-INHERIT/'
        url = url + 'domains/' + domain + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/' + role + '/'
        url = url + 'inherited_to_projects'
        
        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('HEAD').content)

        return resp


    def revoke_inherit_role(self, domain, user, role):
        url = self.keystone_url + 'OS-INHERIT/'
        url = url + 'domains/' + domain + '/'
        url = url + 'users/' + user + '/'
        url = url + 'roles/' + role + '/'
        url = url + 'inherited_to_projects'

        header = self._generate_common_headers()
        header["X-Auth-token"] = self.generate_token_id()
        
        request = HttpRequest(url, headers=header)
        resp = json.loads(request.call('DELETE').content)

        return resp


    def _generate_common_headers(self):
        header = {
            "Content-type": "application/json"
            }

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
        resp = json.loads(request.call("POST").content)

        return resp
