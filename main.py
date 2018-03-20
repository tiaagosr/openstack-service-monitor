import imports
from modules.link_metering import LinkMetering
from modules.api_logging import ApiLogging
from modules.plotting import DataPlotting
#from database import DBSession
#wlp2s0
#'enp0s20u3'
#current_interface = 'enp0s20u3'
current_interface = 'wlp2s0'
db_file = ':memory:'

#api_logging = ApiLogging(iface=current_interface, dbpath=':memory:', interval=5, filter='tcp and (dst port 80 or dst port 443)')
#api_logging.start_monitoring()

#link_metering = LinkMetering(iface=current_interface, dbpath=db_file, interval=5)
#link_metering.start_monitoring()

plot = DataPlotting('traffic.db')
plot.gen_link_metering_plot()