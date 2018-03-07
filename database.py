import sqlite3

class DBSession(object):
    _db = None
    _flagConnOpen = False
    sqli_path = ':memory:'
    def __init__(self, func):
        self.func = func
    def __get__(self, obj, type=None):
        return self.__class__(self.func.__get__(obj, type))
    def create_conn(self):
        if(self.__class__._flagConnOpen == False):
            self.__class__._db = sqlite3.connect(self.__class__.sqli_path, isolation_level=None)
            self.__class__._flagConnOpen = True
            cursor = self.__class__._db
            cursor.execute("PRAGMA cache_size = "+str(50*1024*1024))
    def __call__(self, *args, **kw):
        self.create_conn()
        cursor = self.__class__._db.cursor()
        try:
            cursor.execute('BEGIN')
            retval = self.func(cursor, *args, **kw)
            cursor.execute('COMMIT')
        except Exception as e:
            cursor.execute('ROLLBACK')
            retval = None
            raise e
        finally:
            cursor.close()
        return retval


@DBSession
def store_metering_result(cursor, result={}, iface='None', ignored_count=0):
    cursor.execute('''CREATE TABLE IF NOT EXISTS 
                    link_usage(
                        id INTEGER PRIMARY KEY,
                        interface VARCHAR(40),
                        m_etc INTEGER,
                        m_nova INTEGER,
                        m_keystone INTEGER,
                        m_glance INTEGER,
                        m_cinder INTEGER,
                        m_swift INTEGER,
                        ignored_count INTEGER,
                        time DATETIME DEFAULT datetime("now", "localtime")
                    )''')
    cursor.execute('''insert into link_usage (interface, ignored_count, m_cinder, m_etc, m_glance, m_keystone, m_nova, m_swift)
                        values ("{iface}", "{ignored_count}", "{cinder}", "{etc}", "{glance}", "{keystone}", "{nova}", "{swift}")'''
                        .format(iface=iface, ignored_count=str(ignored_count), **result)
                    )
    del result


@DBSession
def print_results(cursor):
    result = cursor.execute("select * from link_usage order by time DESC LIMIT 1")
    print(result.fetchone())