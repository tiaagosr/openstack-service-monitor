import imports
from modules.link_metering import LinkMetering
#from modules.apilogging import start_api_logging
#from database import DBSession
#wlp2s0
#'enp0s20u3'

#start_api_logging()
link_metering = LinkMetering(iface='enp0s20u3', dbpath=':memory:', interval=3)
link_metering.start_monitoring()