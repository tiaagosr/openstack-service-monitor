import imports
from modules.link_metering import LinkMetering
#from modules.apilogging import start_api_logging
from database import DBSession
#wlp2s0
#'enp0s20u3'

persistence = DBSession(':memory:')
#start_api_logging()
link_metering = LinkMetering(iface='wlp2s0', filter='tcp', db=persistence, interval=2)
link_metering.start_monitoring()