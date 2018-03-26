import imports
from modules.link_metering import LinkMetering
#from modules.api_logging import ApiLogging
from modules.plotting import DataPlotting
#from modules.simple_scenario import ScenarioManager
#from database import DBSession
#wlp2s0
#'enp0s20u3'
#current_interface = 'enp0s20u3'
current_interface = 'wlp2s0'
db_file = 'file.db'

if __name__ == '__main__':
    #api_logging = ApiLogging(iface=current_interface, dbpath=':memory:', interval=5)
    #api_logging.start_monitoring()

    #link_metering = LinkMetering(iface=current_interface, dbpath=db_file, interval=5)
    #link_metering.start_monitoring()

    plot = DataPlotting('traffic_etc.db')
    #plot.categorized_metering_plot()
    plot.uncategorized_metering_plot()

    #link_metering = LinkMetering(iface=current_interface, dbpath=db_file, interval=5)
    #link_metering.start_monitoring()

    #scenario = ScenarioManager()
    #scenario.test_scenario(2, ['suspend', 'resume', 'stop'])

    #link_metering.stop_execution()
