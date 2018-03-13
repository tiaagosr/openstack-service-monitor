import imports
from modules.link_metering import LinkMetering
from modules.api_logging import ApiLogging
#from database import DBSession
#wlp2s0
#'enp0s20u3'

api_logging = ApiLogging(iface='enp0s20u3', dbpath=':memory:', interval=3)
api_logging.start_monitoring()

#link_metering = LinkMetering(iface='enp0s20u3', dbpath=':memory:', interval=3)
#link_metering.start_monitoring()
