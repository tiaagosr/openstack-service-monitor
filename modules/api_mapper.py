import re


def equal(packet, attr, value):
    print(getattr(packet, attr, None).decode("utf-8"), " == ", value, " ?")
    return getattr(packet, attr, None).decode("utf-8") == value


def regex(packet, attr, value):
    print("is ", value, " in ", getattr(packet, attr, None).decode("utf-8"), " ?")
    return bool(re.search(value, getattr(packet, attr, None).decode("utf-8")))


ACTIONS = dict()

ACTIONS['nova'] = [
    # VM Main Actions
    {
        'requirement': [
            ('Path', '/servers/?\Z', regex),
        ],
        'actions': [
            {'action': 'List VMs', 'requirement': ('Method', 'GET', equal)},
            {'action': 'Create VM', 'requirement': ('Method', 'POST', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/servers/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Show VM Details', 'requirement': ('Method', 'GET', equal)},
            {'action': 'Change VM Config', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete VM', 'requirement': ('Method', 'DELETE', equal)},
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
            ('Path', '/servers/[a-zA-Z0-9_-]+/os-interface/[a-zA-Z0-9_-]+/?\Z', regex),
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
            {'action': 'List Flavors', 'requirement': ('Method', 'GET', equal)},
        ]},
]

ACTIONS['glance'] = [
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
            {'action': 'Show Image details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/images/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create Image', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List Images', 'requirement': ('Method', 'GET', equal)},
        ]},
]

ACTIONS['neutron'] = [

    #Network Actions
    {
        'requirement': [
            ('Path', '/v2\.0/networks/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update Network', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete Network', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show Network', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/networks/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create Network', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List Networks', 'requirement': ('Method', 'GET', equal)},
        ]},

    #Port Actions
    {
        'requirement': [
            ('Path', '/v2\.0/ports/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update Port', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete Port', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show Port', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/ports/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create Port', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List Ports', 'requirement': ('Method', 'GET', equal)},
        ]},

    #L3 Address Scope
    {
        'requirement': [
            ('Path', '/v2\.0/address-scopes/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update address scope', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete address scope', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show address scope', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/address-scopes/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create address scope', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List address scope', 'requirement': ('Method', 'GET', equal)},
        ]},

    #L3 Floating IP
    {
        'requirement': [
            ('Path', '/v2\.0/address-scopes/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update address scope', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete address scope', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show address scope', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v2\.0/address-scopes/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create address scope', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List address scope', 'requirement': ('Method', 'GET', equal)},
        ]},
]

ACTIONS['cinder'] = [
    #Volume
    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/volumes/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update volume', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete volume', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show volume details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v3/[a-zA-Z0-9_-]+/volumes/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create volume', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List volumes', 'requirement': ('Method', 'GET', equal)},
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

]

ACTIONS['keystone'] = [

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
        'action': 'Get Service Catalog',
        'requirement': [
            ('Method', 'GET', equal),
            ('Path', '/v3/auth/catalog/?\Z', regex)
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
            {'action': 'Show credential details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v3/credentials/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create credential', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List credentials', 'requirement': ('Method', 'GET', equal)},
        ]},

    # Projects
    {
        'requirement': [
            ('Path', '/v3/projects/[a-zA-Z0-9_-]+/?\Z', regex),
        ],
        'actions': [
            {'action': 'Update project', 'requirement': ('Method', 'PUT', equal)},
            {'action': 'Delete project', 'requirement': ('Method', 'DELETE', equal)},
            {'action': 'Show project details', 'requirement': ('Method', 'GET', equal)},
        ]},

    {
        'requirement': [
            ('Path', '/v3/projects/?\Z', regex),
        ],
        'actions': [
            {'action': 'Create project', 'requirement': ('Method', 'POST', equal)},
            {'action': 'List projects', 'requirement': ('Method', 'GET', equal)},
        ]},
]


def get_action(service, packet, api_map=ACTIONS):
    api = api_map[service]
    print("getting action for packet: ")
    packet.show()
    for resource in api:
        print("Verifying resource: ", resource)
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
