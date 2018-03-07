import imports
from modules.linkusage import start_link_metering
from modules.apilogging import start_api_logging

#start_api_logging()
start_link_metering(interval=2, iface='enp0s20u3', filter='tcp', sqli_path=':memory:')