import imports
from modules.link_metering import LinkMetering
#from modules.api_logging import ApiLogging
from modules.plotting import DataPlotting
from modules.simple_scenario import ScenarioManager
#from database import DBSession
#wlp2s0
#'enp0s20u3'
current_interface = 'enp0s20u3'
#current_interface = 'wlp2s0'
db_file = 'results.db'
services=['cinder', 'glance', 'nova', 'neutron']

if __name__ == '__main__':
    #api_logging = ApiLogging(iface=current_interface, dbpath=':memory:', interval=5)
    #api_logging.start_monitoring()

    plot = DataPlotting(db_file, services)
    plot.metering_pie_plot(False)
    #plot.metering_pie_plot(False)

    #scenario = ScenarioManager()
    #scenario.authenticate();
    #scenario.network_cfg();

    #link_metering = LinkMetering(iface=current_interface, dbpath=db_file, interval=10)
    #link_metering.start_monitoring()

    #scenario.test_scenario(1, ['suspend', 'resume', 'stop', 'shelve'])
