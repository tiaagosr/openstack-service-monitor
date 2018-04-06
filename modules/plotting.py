import matplotlib.pyplot as plt
from cycler import cycler
from datetime import datetime
import json
from functools import reduce
from modules.definitions import MonitoringModule
from modules.link_metering import LinkMeteringPersistence


class DataPlotting:
    TRAFFIC_OUTBOUND = MonitoringModule.TRAFFIC_OUTBOUND
    TRAFFIC_INBOUND = MonitoringModule.TRAFFIC_INBOUND

    def __init__(self, dbpath, services=['cinder', 'glance', 'keystone', 'nova', 'swift', 'neutron', 'ceilometer', 'etc']):
        self.db = LinkMeteringPersistence(services, dbpath)
        self.date_format = '%H:%M:%S'
        self.services = services
    
    def get_service_data(self, traffic_type=None):
        db_data = self.db.service_data(traffic_type)
        plot_value = {
            'y': [],
            'services': {x: [] for x in self.services}
        }

        def row_increase(pos, val):
            pos[-1] += val

        def row_append(pos, val):
            pos.append(val)

        for index, row in enumerate(db_data):
            # Every odd row sum its value to the even row before
            # Reason: each metering creates 2 rows, one for inbound traffic and one for outbound traffic
            # The sum only happens if no traffic type was defined
            if index % 2 != 0 and traffic_type is not None:
                row_operation = row_increase
            #Every even row, starting from 0
            else:
                plot_value['y'].append(datetime.strptime(row[0], self.date_format))
                row_operation = row_append
            for column, service in enumerate(plot_value['services'], 1):
                row_operation(plot_value['services'][service], row[column])

        return plot_value

    def get_etc_port_data(self, traffic_type=None):
        db_data = self.db.etc_port_data(traffic_type)

        plot_value = {
            'y': [],
            'ports': {}
        }

        def row_increase(pos, val):
            pos[-1] += val

        def row_append(pos, val):
            pos.append(val)

        for i, row in enumerate(db_data):
            if i % 2 != 0 and traffic_type is not None:
                row_operation = row_increase
            #Every even row, starting from 0
            else:
                plot_value['y'].append(datetime.strptime(row[2], self.date_format))
                row_operation = row_append
            row_port_tuples = json.loads(row[1])
            for port_tuple in row_port_tuples:
                port_value = port_tuple['value']
                port_number = port_tuple['port']
                if port_number not in plot_value['ports']:
                    #Create new port in plotting list
                    plot_value['ports']['port'] = [0] * i
                #New entry to existing port
                row_operation(plot_value['ports'][port_number], port_value)
            current_row_ports_index = list(map(lambda x: x['port'], row_port_tuples))
            not_plotted_port_tuples = [x for x in plot_value['ports'] if x not in current_row_ports_index]
            for port in not_plotted_port_tuples:
                row_operation(plot_value['ports'][port], 0)

        return plot_value

    def format_plot(self, title=''):
        fig, ax = plt.subplots(1, 1, figsize=(12, 9))

        ax.spines['top'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_visible(False)

        ax.get_xaxis().tick_bottom()
        ax.get_yaxis().tick_left()

        cy = cycler('color', ['red', 'green', 'blue', 'yellow', 'orange', 'purple', 'turquoise', 'brown', 'grey', 'cyan'])
        ax.set_prop_cycle(cy)

        plt.title(title)
        plt.grid(True, 'major', 'y', ls='--', lw=.5, c='k', alpha=.3)

        return fig, ax

    def metering_line_plot(self, categorized=True, traffic_type=None):
        if categorized:
            plot_data = self.get_service_data(traffic_type)
            data = plot_data['services']
            legends = data
        else:
            plot_data = self.get_etc_port_data(traffic_type)
            data = plot_data['ports']
            legends = list(map(lambda x: 'TCP port '+str(x), data))

        title = 'Total Traffic'
        if traffic_type == MonitoringModule.TRAFFIC_OUTBOUND:
            title = 'Outbound Traffic'
        elif traffic_type == MonitoringModule.TRAFFIC_INBOUND:
            title = 'Inbound Traffic'
        self.format_plot(title)

        for line in data:
            plt.plot(plot_data['y'], data[line])

        plt.legend(legends, loc='upper left')
        plt.show()

    def metering_pie_plot(self, categorized=True, traffic_type=None):
        if categorized:
            plot_data = self.get_service_data(traffic_type)
            data = plot_data['services']
            legends = data
        else:
            plot_data = self.get_etc_port_data(traffic_type)
            data = plot_data['ports']
            legends = list(map(lambda x: 'TCP port '+str(x), data))

        title = 'Total Traffic'
        if traffic_type == MonitoringModule.TRAFFIC_OUTBOUND:
            title = 'Outbound Traffic'
        elif traffic_type == MonitoringModule.TRAFFIC_INBOUND:
            title = 'Inbound Traffic'
        fig1, ax1 = self.format_plot(title)

        sizes = []
        for line in data:
            sizes.append(reduce((lambda x, y: x + y), data[line]))
        legends = [x for index, x in enumerate(legends) if sizes[index] > 0]
        sizes = [x for x in sizes if x > 0]
        explode = (0, 0.1, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

        ax1.pie(sizes, labels=legends, autopct='%1.1f%%',
            startangle=90)
        ax1.axis('equal')
        plt.show()