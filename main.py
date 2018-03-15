import imports
from modules.link_metering import LinkMetering
from modules.api_logging import ApiLogging
#from database import DBSession
#wlp2s0
#'enp0s20u3'
current_interface = 'enp0s20u3'
#start_api_logging()
api_logging = ApiLogging(iface=current_interface, dbpath=':memory:', interval=3)
api_logging.start_monitoring()

#link_metering = LinkMetering(iface=current_interface, dbpath=':memory:', interval=3)
#link_metering.start_monitoring()