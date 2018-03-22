import time, os, sys
import inspect
from os import environ as env
from novaclient import client
import keystoneclient.v3.client as ksclient
from keystoneauth1 import loading, session
from definitions import MonitoringModule

class SimpleScenario(MonitoringModule):

    def __init__(self, flavor="m1.small", image="ubuntu 14.04"):
        self.flavor = flavor
        self.image = image
        self.private_net = None
        self.floating_ip_pool_name = None
        self.floating_ip = None


loader = loading.get_plugin_loader('password')
auth = loader.load_from_options(auth_url=env['OS_AUTH_URL'],
                                username=env['OS_USERNAME'],
                                password=env['OS_PASSWORD'],
                                project_name=env['OS_PROJECT_NAME'],
                                user_domain_name=env['OS_USER_DOMAIN_NAME'],
                                project_domain_name=env['OS_PROJECT_DOMAIN_NAME'])


sess = session.Session(auth=auth)
nova = client.Client('2.1', session=sess)
print "user authorization completed."

image = nova.images.find(name="ubuntu 14.04")
flavor = nova.flavors.find(name=flavor)

if private_net != None:
    net = nova.networks.find(label=private_net)
    nics = [{'net-id': net.id}]
else:
    sys.exit("private-net not defined.")

secgroup = nova.security_groups.find(name="default")
secgroups = [secgroup.id]

#floating_ip = nova.floating_ips.create(nova.floating_ip_pools.list()[0].name)

if floating_ip_pool_name != None: 
    floating_ip = nova.floating_ips.create(floating_ip_pool_name)
else: 
    sys.exit("public ip pool name not defined.")


print "Creating instance ... "
instance = nova.servers.create(name="vm1", image=image, flavor=flavor, nics=nics,security_groups=secgroups)
inst_status = instance.status
print "waiting for 10 seconds.. "
time.sleep(10)

while inst_status == 'BUILD':
    print "Instance: "+instance.name+" is in "+inst_status+" state, sleeping for 5 seconds more..."
    time.sleep(5)
    instance = nova.servers.get(instance.id)
    inst_status = instance.status

print "Instance: "+ instance.name +" is in " + inst_status + "state"

if floating_ip != None: 
    instance.add_floating_ip(floating_ip)
    print "Instance booted! Name: " + instance.name + " Status: " +instance.status+ ", No floating IP attached"
else:
    print "Instance booted! Name: " + instance.name + " Status: " +instance.status+ ", Floating IP: " + floating_ip.ip 
