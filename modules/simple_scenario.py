from os import environ as env
from keystoneauth1.identity import v3
from keystoneauth1 import session
from glanceclient import Client as glanceclient
from neutronclient.v2_0 import client as neutronclient
from novaclient import client as novaclient
import time
# from definitions import MonitoringModule

class ScenarioManager():

    def __init__(self, flavor="m1.small", image="trusty-server", auth_data=None):
        self.flavor = flavor
        self.image = image
        self.nics = None
        self.count = 1
        self.session = None
        self.vms = {}
        if auth_data is None:
            self.auth_data = {
                'auth_url': env['OS_AUTH_URL'],
                'username': env['OS_USERNAME'],
                'password': env['OS_PASSWORD'],
                'project_name': env['OS_PROJECT_NAME'],
                'user_domain_name': env['OS_USER_DOMAIN_NAME'],
                'project_domain_name': env['OS_PROJECT_DOMAIN_NAME']
             }
        else:
            self.auth_data = auth_data

    def authenticate(self):
        if self.session is None:
            auth = v3.Password(**self.auth_data)
            self.session = session.Session(auth=auth)
        return self.session

    def network_cfg(self):
        if self.nics is None:
            session = self.authenticate()
            neutron = neutronclient.Client(session=session)
            # https://developer.openstack.org/api-ref/network/v2/#create-network
            network_request = {
                'network': {
                    'name': 'local',
                    'admin_state_up': True
                }
            }

            response = neutron.create_network(network_request)
            network_id = response['network']['id']
            self.nics = [{'net-id': network_id}]

            # https://developer.openstack.org/api-ref/network/v2/#create-subnet
            subnet_request = {
                "subnet": {
                    "name": "Subnet1",
                    "network_id": network_id,
                    "ip_version": 4,
                    "cidr": "192.168.0.0/24"
                }
            }
            neutron.create_subnet(subnet_request)
        return self.nics

    def get_vm_status(self, name):
        session = self.authenticate()
        nova = novaclient.Client('2.1', session=session)
        response = nova.servers.list(search_opts={'uuid': self.vms[name].id})
        self.vms['name'] = response[0]
        return response[0].status

    def vm_create(self, image=None, flavor=None, name=None):
        if image is None:
            image = self.image
        if flavor is None:
            flavor = self.flavor
        if name is None:
            name = "vm" + str(self.count)
            self.count += 1
        session = self.authenticate()

        nics = self.network_cfg()

        nova = novaclient.Client('2.1', session=session)
        glance = glanceclient('2', session=session)

        vm_flavor = nova.flavors.find(name=flavor)
        images = list(glance.images.list())

        image_mapping = {x['name']: x['id'] for x in images}
        vm_image = image_mapping[image]

        instance = nova.servers.create(name, vm_image, vm_flavor, nics=nics)
        self.vms[name] = instance
        return name

    def vm_set_state(self, name, state):
        # https://docs.openstack.org/nova/latest/reference/vm-states.html
        state_dict = {
            'suspend': {'condition': ['ACTIVE', 'SHUTOFF'], 'function': (lambda x: x.suspend())},
            'resume': {'condition': ['SUSPENDED'], 'function': (lambda x: x.resume())},
            'reboot': {'condition': ['ACTIVE', 'SHUTOFF', 'RESCUED'], 'function': (lambda x: x.reboot())},
            'shelve': {'condition': ['ACTIVE', 'SHUTOFF', 'SUSPENDED'], 'function': (lambda x: x.shelve())},
            'stop': {'condition': ['ACTIVE', 'SHUTOFF', 'RESCUED'], 'function': (lambda x: x.stop())}
        }

        print("vm state: "+self.get_vm_status(name))
        if name in self.vms and state in state_dict and self.get_vm_status(name) in state_dict[state]['condition']:
            return state_dict[state]['function'](self.vms[name])

    def test_scenario(self, vm_count=1, state_list=['stop'], sleep=120):
        vm_list = []
        for i in range(vm_count):
            vm_list.append(self.vm_create())
        print('VMs Created!')
        for state in state_list:
            print('Changing vms state to '+state)
            time.sleep(sleep)
            for vm in vm_list:
                self.vm_set_state(vm, state)
        time.sleep(sleep)
        print('Scenario Finished!')
        exit()

