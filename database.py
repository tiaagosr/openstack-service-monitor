import sqlite3

class DBSession(object):
    def __init__(self, path=':memory'):
        self.sqli_path = path
        self.db = None
        
    def create_conn(self):
        if(self.db is None):
            self.db = sqlite3.connect(self.sqli_path, isolation_level=None)
            cursor = self.db
            cursor.execute("PRAGMA cache_size = "+str(50*1024*1024))

    def wrap_access(self, func, *args, **kw):
        self.create_conn()
        cursor = self.db.cursor()
        try:
            cursor.execute('BEGIN')
            retval = func(cursor, *args, **kw)
            cursor.execute('COMMIT')
        except Exception as e:
            cursor.execute('ROLLBACK')
            retval = None
            raise e
        finally:
            cursor.close()
        return retval