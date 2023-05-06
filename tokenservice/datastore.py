import sqlite3


class DataStore:
    CREATE_ISSUED = """
       CREATE TABLE IF NOT EXISTS ISSUED
       (ID INT PRIMARY KEY NOT NULL, TOKEN TEXT, EXPIRE REAL);"""

    def __init__(self, config):
        dbfile = config['file']
        self.conn = sqlite3.connect(dbfile)
        self.conn.execute(DataStore.CREATE_ISSUED)

    def __del__(self):
        self.conn.close()

    def insert(self, id, token, expire):
        sql = "INSERT INTO ISSUED VALUES('{}','{}',{});".format(id, token, expire)
        self.conn.execute(sql)
        self.conn.commit()

    def select_by_id(self, id):
        sql = "SELECT token, expire from ISSUED where id='{}';".format(id)
        cursor = self.conn.execute(sql)
        token, expire = None, -1
        for token, expire in cursor:
            break
        return token, expire

    def update_token_expire(self, id, ts):
        sql = "UPDATE ISSUED set expire={} where id='{}';".format(ts, id)
        self.conn.execute(sql)
        self.conn.commit()

    def delete(self, id: str):
        sql = "DELETE FROM ISSUED where id='{}';".format(id)
        self.conn.execute(sql)
        self.conn.commit()

    def select_all_ids(self):
        sql = "SELECT id from ISSUED;".format(id)
        cursor = self.conn.execute(sql)
        return [id for (id) in cursor]
