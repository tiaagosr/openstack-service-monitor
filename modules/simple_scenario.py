import time, os, sys
from os import environ as env
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as kc
from glanceclient import Client as glanceclient
from neutronclient.v2_0 import client as neutronclient
from novaclient import client as novaclient
#from definitions import MonitoringModule

class ScenarioManager():

    def __init__(self, flavor="m1.small", image="trusty-server"):
        self.flavor = None #"m1.small"
        self.image = None #"trusty-server"
        self.private_net = None #"local"
        self.floating_ip_pool_name = None
        self.floating_ip = None
        self.session = None

        self.get_available_configs(image, flavor)

    def authenticate(self):
        if self.session is None:
            auth = v3.Password(auth_url=env['OS_AUTH_URL'], username=env['OS_USERNAME'], password=env['OS_PASSWORD'], project_name=env['OS_PROJECT_NAME'], user_domain_name=env['OS_USER_DOMAIN_NAME'], project_domain_name=env['OS_PROJECT_DOMAIN_NAME'])        
            self.session = session.Session(auth=auth)
        return self.session

    def get_available_configs(self, image='', flavor=''):
        confs = {
            'flavor': '',
            'image': '',
            'name':'vm1'
            }

        session = self.authenticate()

        nova = novaclient.Client('2.1', session=session)
        glance = glanceclient('2', session=session)
        neutron = neutronclient.Client(session=session)

        flavor_result = nova.flavors.find(name=flavor)
        images = list(glance.images.list())

        neutron.create_network({'network': {'name': 'mynetwork', 'admin_state_up': True}})
        networks = neutron.list_networks(name='mynetwork')[0]
        
        image_mapping = {x['name']:x['id'] for x in images}
        if image in image_mapping:
            confs['image'] = image_mapping[image]
        confs['flavor'] = flavor_result
        print(confs)

        instance = nova.servers.create('vm1', confs['image'], confs['flavor'], networks)
        inst_status = instance.status
        print(inst_status)
        return confs

        '''
        print(nova.servers.list())
        print(nova.flavors.list())
        print(nova.images.list())
        
        print("user authorization completed.")

        image = nova.images.find(name=self.image)
        flavor = nova.flavors.find(name=self.flavor)

        if self.private_net != None:
            net = nova.networks.find(label=self.private_net)
            nics = [{'net-id': net.id}]
        else:
            sys.exit("private-net not defined.")

        secgroup = nova.security_groups.find(name="default")
        secgroups = [secgroup.id]

        #floating_ip = nova.floating_ips.create(nova.floating_ip_pools.list()[0].name)

        if self.floating_ip_pool_name != None: 
            floating_ip = nova.floating_ips.create(self.floating_ip_pool_name)
        else: 
            sys.exit("public ip pool name not defined.")
        nova.servers.create(name="vm1", image="trusty-server", flavor="m1.small", nics="local", security_groups="default")
        print("Creating instance ... ")
        instance = nova.servers.create(name="vm1", image=image, flavor=flavor, nics=nics, security_groups=secgroups)
        inst_status = instance.status
        print("waiting for 10 seconds.. ")
        time.sleep(10)

        while inst_status == 'BUILD':
            print("Instance: "+instance.name+" is in "+inst_status+" state, sleeping for 5 seconds more...")
            time.sleep(5)
            instance = nova.servers.get(instance.id)
            inst_status = instance.status

        print("Instance: "+ instance.name +" is in " + inst_status + "state")

        if floating_ip != None: 
            instance.add_floating_ip(floating_ip)
            print("Instance booted! Name: " + instance.name + " Status: " +instance.status+ ", No floating IP attached")
        else:
            print("Instance booted! Name: " + instance.name + " Status: " +instance.status+ ", Floating IP: " + floating_ip.ip)
'''