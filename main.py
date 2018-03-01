import imports
from modules.linkusage import start_link_metering
from modules.apilogging import start_api_logging

start_api_logging()
#start_link_metering(interval=10, iface='wlp2s0', filter='tcp',sqli_path=':memory:')