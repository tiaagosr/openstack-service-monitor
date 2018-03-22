import matplotlib.pyplot as plt
from cycler import cycler
import numpy as np
from datetime import datetime
from database import DBSession
import json

class DataPlotting():
    def __init__(self, dbpath):
        self.db = DBSession(dbpath)
        self.db.create_conn()
        self.date_format = '%Y-%m-%d %H:%M:%S'
        self.services = ['cinder', 'glance', 'keystone', 'nova', 'swift']
    
    def get_services_db_data(self):
        db_data = self.db.wrap_access(self._db_categorized_metering_data)
        plot_value = {
            'y': [],
            'cinder': [],
            'etc': [],
            'glance': [],
            'keystone': [],
            'nova': [],
            'swift': []
        }

        for row in db_data:
            plot_value['cinder'].append(row[0])
            plot_value['etc'].append(row[1])
            plot_value['glance'].append(row[2])
            plot_value['keystone'].append(row[3])
            plot_value['nova'].append(row[4])
            plot_value['swift'].append(row[5])
            plot_value['y'].append(datetime.strptime(row[6], self.date_format))

        return plot_value

    def get_etc_ports_db_data(self):
        db_data = self.db.wrap_access(self._db_uncategorized_metering_data)
        db_ports_data = self.db.wrap_access(self._db_uncategorized_first_result)

        plot_value = {
            'y': [],
        }

        if db_ports_data is not None:
            etc_ports = json.loads(db_ports_data['etc_ports'])
            for port in etc_ports:
                plot_value[port] = []

        for row in db_data:
            etc_port_metering = json.loads(row[1])
            for port in (x for x in etc_port_metering if x in plot_value):
                plot_value[port].append(etc_port_metering[port])
            for port in (x for x in plot_value if x not in etc_port_metering):
                plot_value[port].append(0)

            plot_value['y'].append(datetime.strptime(row[2], self.date_format))

        return plot_value

    def format_plot(self):
        fig, ax = plt.subplots(1, 1, figsize=(12, 9))

        ax.spines['top'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_visible(False)

        ax.get_xaxis().tick_bottom()
        ax.get_yaxis().tick_left()

        cy = cycler('color', ['red', 'green', 'blue', 'yellow', 'orange', 'purple'])
        ax.set_prop_cycle(cy)

        plt.grid(True, 'major', 'y', ls='--', lw=.5, c='k', alpha=.3)

        return fig, ax

    def categorized_metering_plot(self):
        plot_data = self.get_services_db_data()
        self.format_plot()

        service_list = [x for x in plot_data if x != 'y']
        for service in service_list:
            plt.plot(plot_data['y'], plot_data[service], label=service)

        plt.legend(service_list, loc='upper left')
        plt.show()

    def uncategorized_metering_plot(self):
        plot_data = self.get_etc_ports_db_data()
        self.format_plot()

        port_list = [x for x in plot_data if x != 'y']
        for port in port_list:
            plt.plot(plot_data['y'], plot_data[port], label=port)

        plt.legend(port_list, loc='upper left')
        plt.show()


    def _db_categorized_metering_data(self, cursor):
        cursor.execute('SELECT m_cinder, m_etc, m_glance, m_keystone, m_nova, m_swift, time FROM link_usage ORDER BY id')
        return cursor.fetchall()

    def _db_uncategorized_metering_data(self, cursor):
        cursor.execute('SELECT m_etc, etc_ports, time FROM link_usage ORDER BY id')
        return cursor.fetchall()

    def _db_uncategorized_first_result(self, cursor):
        cursor.execute('SELECT etc_ports FROM link_usage ORDER BY id')
        return cursor.fetchone()