import sqlite3

class DBSession(object):
    _db = None
    _flagConnOpen = False
    def __init__(self, func):
        self.func = func
    def __get__(self, obj, type=None):
        return self.__class__(self.func.__get__(obj, type))
    def createConn(self):
        if(self.__class__._flagConnOpen == False):
            self.__class__._db = sqlite3.connect(':memory:')
            self.__class__._flagConnOpen = True
    def __call__(self, *args, **kw):
        self.createConn()
        cursor = self.__class__._db.cursor()
        try:
            cursor.execute("BEGIN")
            retval = self.func(cursor, *args, **kw)
            cursor.execute("COMMIT")
        except Exception as e:
            cursor.execute("ROLLBACK")
            retval = None
            raise e
        finally:
            cursor.close()
        return retval


@DBSession
def storeResult(cursor, result, interface, ignored_count):
    cursor.execute('''CREATE TABLE IF NOT EXISTS 
                    link_usage(
                        id INTEGER PRIMARY KEY, 
                        interface VARCHAR(40), 
                        result INTEGER,
                        ignored_count INTEGER,
                        time DATETIME DEFAULT CURRENT_TIMESTAMP
                    )''')
    cursor.execute('''insert into bandwidth (interface, ignored_count, result)
                        values ("{interface}", "{ignored_count}", "{result}")'''
                        .format(interface=interface, ignored_count=str(ignored_count), result=str(result))
                    )


@DBSession
def printMeasurements(cursor):
    result = cursor.execute("select * from bandwidth")
    print(result.fetchall())