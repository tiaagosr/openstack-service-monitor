import re


def equal(packet, attr, value):
    print(getattr(packet, attr, None).decode("utf-8"), " == ", value, " ?")
    return getattr(packet, attr, None).decode("utf-8") == value


def regex(packet, attr, value):
    print("is ", value, " in ", getattr(packet, attr, None).decode("utf-8"), " ?")
    return bool(re.search(value, getattr(packet, attr, None).decode("utf-8")))

ACTIONS = dict()

ACTIONS['nova'] = [
    #Options
    {
        'action': 'OPTIONS',
        'requirement': [
            ('Method', 'OPTIONS', equal),
            ('Path', '/\Z', regex)
        ]},

    # VM Main Actions
    {
        'requirement': [
            ('Path', '/servers/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create VM', 'requirement': ('Method', 'POST', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/servers/[a-zA-Z0-9_-]+(?:\.json)?/?\Z', regex),
        ],
        'actions': [
            {'action': 'Change VM Config', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete VM', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get vm info',
        'requirement': [
            ('Path', '/servers(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    # VM States
    {
        'requirement': [
            ('Method', 'POST', equal),
            ('Path', '/servers/[a-zA-Z0-9_-]+/action/?\Z', regex),
        ],
        'actions': [
            {'action': 'Start VM', 'requirement': ('load', '"os-start"', regex)},
            {'action': 'Stop VM', 'requirement': ('load', '"os-stop"', regex)},
            {'action': 'Suspend VM', 'requirement': ('load', '"suspend"', regex)},
            {'action': 'Pause VM', 'requirement': ('load', '"pause"', regex)},
            {'action': 'Reboot VM', 'requirement': ('load', '"reboot"', regex)},
            {'action': 'Shelve VM', 'requirement': ('load', '"shelve"', regex)},
            {'action': 'Shelve-Offload VM', 'requirement': ('load', '"shelveOffload"', regex)},
            {'action': 'Migrate VM', 'requirement': ('load', '"migrate"', regex)},
            {'action': 'Live-Migrate VM', 'requirement': ('load', '"os-migrateLive"', regex)},
        ]},

    # VM Port Interface
    {
        'requirement': [
            ('Path', '/servers/[a-zA-Z0-9_-]+/os-interface/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create VM Interface', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List VM Interfaces', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/servers/[a-zA-Z0-9_-]+/os-interface/[a-zA-Z0-9_-]+(?:\.json)?/?\Z', regex),
        ],
        'actions': [
            {'action': 'Show Interface Details', 'requirement': ('Method', 'GET', equal)},
            {'action': 'Detach Interface', 'requirement': ('Method', 'GET', equal)},
        ]},

    # VM Volume Attachment
    {
        'requirement': [
            ('Path', '/servers/[a-zA-Z0-9_-]+/os-volume_attachments/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update volume attachment', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Detach volume', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show volume attachment details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/servers/[a-zA-Z0-9_-]+/os-volume_attachments/?\Z', regex),
        ],
        'actions': [
            {'action': 'Attach volume to VM', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List VM attachments', 'requirement': ('Method', 'GET', equal)},
        ]},

    # Flavor
    {
        'requirement': [
            ('Path', '/flavors/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create Flavor', 'requirement': ('Method', 'POST', equal)},
        ]},

    {
        'action': 'Get flavor info',
        'requirement': [
            ('Path', '/flavors(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},
]

ACTIONS['glance'] = [
    #Options
    {
        'action': 'OPTIONS',
        'requirement': [
            ('Method', 'OPTIONS', equal),
            ('Path', '/\Z', regex)
        ]},

    {
        'action': 'Healthcheck',
        'requirement': [
            ('Method', 'GET', equal),
            ('Path', '/healthcheck', regex)
        ]},

    #Image
    {
        'requirement': [
            ('Path', '/v2\.0/images/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update Image', 'requirement': ('Method', 'PATCH', equal)},
            {'action': 'Delete Image', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get image info',
        'requirement': [
            ('Path', '/v2\.0/images(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/images/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create Image', 'requirement': ('Method', 'POST', equal)},
        ]},
]

ACTIONS['neutron'] = [
    #Options
    {
        'action': 'OPTIONS',
        'requirement': [
            ('Method', 'OPTIONS', equal),
            ('Path', '/\Z', regex)
        ]},

    #Network Actions
    {
        'requirement': [
            ('Path', '/v2\.0/networks(?:\.json/[a-zA-Z0-9_-]+/?\Z)', regex),
        ],
        'actions': [
            {'action': 'Update Network', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete Network', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get network info',
        'requirement': [
            ('Path', '/v2\.0/networks(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/networks/?\Z', regex),
            ('Method', 'POST', equal)
        ],
        'action': 'Create network'
    },

    #Port Actions
    {
        'requirement': [
            ('Path', '/v2\.0/ports(?:\.json/[a-zA-Z0-9_-]+/?\Z)', regex),
        ],
        'actions': [
            {'action': 'Update Port', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete Port', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get port info',
        'requirement': [
            ('Path', '/v2\.0/ports(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/port/?\Z', regex),
            ('Method', 'POST', equal)
        ],
        'action': 'Create port'
    },

    #L3 Address Scope
    {
        'requirement': [
            ('Path', '/v2\.0/adresses-scopes(?:\.json/[a-zA-Z0-9_-]+/?\Z)', regex),
        ],
        'actions': [
            {'action': 'Update adress scope', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete adress scope', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get adress scope info',
        'requirement': [
            ('Path', '/v2\.0/adresses-scopes(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    #Subnet
    {
        'requirement': [
            ('Path', '/v2\.0/subnets(?:\.json/[a-zA-Z0-9_-]+/?\Z)', regex),
        ],
        'actions': [
            {'action': 'Update Subnet', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete Subnet', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get Subnet info',
        'requirement': [
            ('Path', '/v2\.0/subnets(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/subnets/?\Z', regex),
            ('Method', 'POST', equal)
        ],
        'action': 'Create Subnet'
    },

    #L3 Floating IP
    {
        'requirement': [
            ('Path', '/v2\.0/floatingips(?:\.json/[a-zA-Z0-9_-]+/?\Z)', regex),
        ],
        'actions': [
            {'action': 'Update floating IP', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete floating IP', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get floating IP info',
        'requirement': [
            ('Path', '/v2\.0/floatingips(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/floatingips/?\Z', regex),
            ('Method', 'POST', equal)
        ],
        'action': 'Create floating IP'
    },
]

ACTIONS['cinder'] = [
    #Options
    {
        'action': 'OPTIONS',
        'requirement': [
            ('Method', 'OPTIONS', equal),
            ('Path', '/\Z', regex)
        ]},

    #Volume
    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/volumes/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update volume', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete volume', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get volume info',
        'requirement': [
            ('Path', '/v3/volumes(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/volumes/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create volume', 'requirement': ('Method', 'POST', equal)},
        ]},

    # Volume metadata
    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/volumes/[a-zA-Z0-9_-]+/metadata/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update volume metadata', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Create volume metadata', 'requirement': ('Method', 'POST', equal)},
            {'action': 'Show volume metadata', 'requirement': ('Method', 'GET', equal)},
        ]},

    # Volume States
    {
        'requirement': [
            ('Method', 'POST', equal),
            ('Path', '/v3/[a-zA-Z0-9_-]+/volumes/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Extend volume size', 'requirement': ('load', '"os-extend"', regex)},
            {'action': 'Reset volume status', 'requirement': ('load', '"os-reset_status"', regex)},
            {'action': 'Attach volume to VM', 'requirement': ('load', '"os-attach"', regex)},
            {'action': 'Detach volume from vm', 'requirement': ('load', '"os-detach"', regex)},
            {'action': 'Upload volume to image', 'requirement': ('load', '"os-volume_upload_image"', regex)},
        ]},

    #Volume snapshot
    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/snapshots/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update snapshot', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete snapshot', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show snapshot details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/snapshots/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create snapshot', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List snapshots', 'requirement': ('Method', 'GET', equal)},
        ]},

    #Volume attachment
    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/attachments/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update snapshot', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete snapshot', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show snapshot details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/attachments/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create snapshot', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List snapshots', 'requirement': ('Method', 'GET', equal)},
        ]},

    #Backup
    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/backups/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update backup', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete backup', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show backup details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/backups/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create backup', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List backups for project', 'requirement': ('Method', 'GET', equal)},
        ]},

    # Method    = 'GET'
    # Path      = '/v1/86fc2178701a4bfea5ca69c5ee5314cc/volumes/detail?all_tenants=1'

]

ACTIONS['keystone'] = [

    #Options
    {
        'action': 'OPTIONS',
        'requirement': [
            ('Method', 'OPTIONS', equal),
            ('Path', '/\Z', regex)
        ]},

    #Healthcheck
    {
        'action': 'Healthcheck',
        'requirement': [
            ('Method', 'GET', equal),
            ('Path', '/v3\Z', regex)
        ]},

    # Authenticate
    {
        'requirement': [
            ('Path', '/v3/auth/tokens/?\Z', regex),
            ('Method', 'POST', equal)
        ],
        'actions': [
            {'action': 'Password Auth', 'requirement': ('load', '"password"', regex)},
            {'action': 'Token Auth', 'requirement': ('load', '"token"', regex)},
            {'action': 'Application credential Auth', 'requirement': ('load', '"application_credential"', regex)},
        ]},

    {
        'action': 'Validate and show token information',
        'requirement': [
            ('Method', 'GET', equal),
            ('Path', '/v3/auth/tokens/?\Z', regex)
        ]},

    # Authenticate V2
    {
        'requirement': [
            ('Path', '/v2/auth/tokens/?\Z', regex),
            ('Method', 'POST', equal)
        ],
        'actions': [
            {'action': 'Password Auth', 'requirement': ('load', '"password"', regex)},
            {'action': 'Token Auth', 'requirement': ('load', '"token"', regex)},
            {'action': 'Application credential Auth', 'requirement': ('load', '"application_credential"', regex)},
        ]},

    {
        'action': 'Validate and show token information',
        'requirement': [
            ('Method', 'GET', equal),
            ('Path', '/v2/auth/tokens/?\Z', regex)
        ]},

    {
        'action': 'Get Service Catalog',
        'requirement': [
            ('Path', '/v3/auth/catalog(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},


    # Application Credential
    {
        'requirement': [
            ('Path', '/v3/users/[a-zA-Z0-9_-]+/application_credentials/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Delete application credential', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show application credential details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v3/users/[a-zA-Z0-9_-]+/application_credentials/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create application credential', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List application credentials', 'requirement': ('Method', 'GET', equal)},
        ]},

    # Credential
    {
        'requirement': [
            ('Path', '/v3/credentials/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update credential', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete crede/v3/credentialsntial', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get credential info',
        'requirement': [
            ('Path', '/v3/credentials(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v3/credentials/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create credential', 'requirement': ('Method', 'POST', equal)},
        ]},

    # Projects
    {
        'requirement': [
            ('Path', '/v3/projects/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update project', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete project', 'requirement': ('Method', 'DELETE', equal)},
        ]},

    {
        'action': 'Get project info',
        'requirement': [
            ('Path', '/v3/projects(?:/?\Z|\.json(?:\?[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+(?:\&[a-zA-Z0-9_\.\%-]+=[a-zA-Z0-9_\.\%-]+)*)?\Z)', regex),
            ('Method', 'GET', equal),
        ]},

    {
        'requirement': [
            ('Path', '/v3/projects/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create project', 'requirement': ('Method', 'POST', equal)},
        ]},
]


def get_action(service, packet, api_map=ACTIONS):
    api = api_map[service]
    packet.show()
    for resource in api:
        action = verify_resource(packet, resource)
        if action is not None:
            return action
    return 'unmapped'


def verify_resource(packet, resource):
    reqs = resource['requirement']
    for req in reqs:
        print("Verifying req: ", req)
        if not req[2](packet, req[0], req[1]):
            print("req false, ignoring resource")
            return None
    if 'action' in resource:
        return resource['action']
    for entry in resource['actions']:
        req = entry['requirement']
        if req[2](packet, req[0], req[1]):
            return entry['action']
    return None
