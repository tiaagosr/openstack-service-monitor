import matplotlib.pyplot as plt
from cycler import cycler
from datetime import datetime
from database import DBSession
import json
from functools import reduce

from modules.definitions import MonitoringModule


class DataPlotting():
    def __init__(self, dbpath, services=['cinder', 'glance', 'keystone', 'nova', 'swift', 'neutron', 'ceilometer']):
        self.db = DBSession(dbpath)
        self.db.create_conn()
        self.date_format = '%H:%M:%S'
        self.services = services
    
    def get_service_data(self, traffic_type=None):
        db_data = self.db.wrap_access(self._db_service_data, traffic_type)
        plot_value = {
            'y': [],
            'etc': [],
            'services': {}
        }

        for service in self.services:
            plot_value['services'][service] = []

        i = 0
        for row in db_data:
            # Every odd row sum its value to the even row before
            # Reason: each metering creates 2 rows, one for inbound traffic and one for outbound traffic
            # The sum only happens if no traffic type was defined
            if i % 2 != 0 and traffic_type is not None:
                def row_operation(pos, val):
                    pos[-1] += val
            #Every even row, starting from 0
            else:
                plot_value['y'].append(datetime.strptime(row[0], self.date_format))

                def row_operation(pos, val):
                    pos.append(val)

            row_operation(plot_value['etc'], row[1])
            cur_row = 2
            for service in plot_value['services']:
                row_operation(plot_value['services'][service], row[cur_row])
                cur_row += 1
            i += 1

        return plot_value

    def get_etc_port_data(self, traffic_type=None):
        db_data = self.db.wrap_access(self._db_etc_port_data, traffic_type)
        db_port_list = self.db.wrap_access(self._db_etc_port_list, traffic_type)

        plot_value = {
            'y': [],
            'ports': {}
        }

        if db_port_list is not None:
            etc_ports = json.loads(db_port_list[0])
            for port in etc_ports:
                plot_value['ports'][port[0]] = []

        i = 0
        for row in db_data:
            if i % 2 != 0 and traffic_type is not None:
                def row_operation(pos, val):
                    pos[-1] += val
            #Every even row, starting from 0
            else:
                plot_value['y'].append(datetime.strptime(row[2], self.date_format))

                def row_operation(pos, val):
                    pos.append(val)
            etc_port_tuples = json.loads(row[1])
            plotted_port_tuples = [x for x in etc_port_tuples if x[0] in plot_value]
            ports_index = list(map(lambda x: x[0], etc_port_tuples))
            not_plotted_port_tuples = [x for x in plot_value['ports'] if x not in ports_index]
            for port in plotted_port_tuples:
                row_operation(plot_value['ports'][port[0]], port[1])
            for port in not_plotted_port_tuples:
                row_operation(plot_value['ports'][port], 0)
            i += 1

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
            plt.plot(plot_data['y'], plot_data['etc'])
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
        self.format_plot(title)

        sizes = []
        for line in data:
            sizes.append(reduce((lambda x, y: x + y), line))
        explode = (0, 0.1, 0, 0)  # only "explode" the 2nd slice (i.e. 'Hogs')

        fig1, ax1 = plt.subplots()
        ax1.pie(sizes, explode=explode, labels=legends, autopct='%1.1f%%',
                shadow=True, startangle=90)
        ax1.axis('equal')
        plt.show()

    def _db_metering_query(self, fields: list[str], traffic_type=None) -> str:
        query = 'SELECT '
        first = True
        # Generate query based on service list
        for f in fields:
            if first:
                first = False
                query += f+' '
            else:
                query += ', '+f
        query += ' FROM link_usage'
        if traffic_type is not None:
            query += 'where type="{type}"'.format(type=traffic_type)
        query += ' ORDER BY id'
        return query

    def _db_service_data(self, cursor, traffic_type=None):
        fields = ['time', 'm_etc']
        for service in self.services:
            fields.append('m_'+service)
        query = self._db_metering_query(fields, traffic_type)
        cursor.execute(query)
        return cursor.fetchall()

    def _db_etc_port_data(self, cursor, traffic_type):
        fields = ['m_etc', 'etc_ports', 'time', 'type']
        query = self._db_metering_query(fields, traffic_type)
        cursor.execute(query)
        return cursor.fetchall()

    def _db_etc_port_list(self, cursor, traffic_type):
        fields = ['etc_ports', 'type']
        query = self._db_metering_query(fields, traffic_type)
        cursor.execute(query)
        return cursor.fetchone()