import MySQLdb

class EmptyDeepRef:
    def __init__(self, default_value="N/A"):
        self.default_value = default_value

    def __getitem__(self, key):
        return self

    def __contains__(self, key):
        return False

    def __str__(self):
        return self.default_value

    def __repr__(self):
        return self.default_value
    
class ConnectionContext:
    def __init__(self, mysql_config):
        self.mysql_opts = mysql_config
        
        self.conn = None
        self.cursor = None

    def __enter__(self):
        self.conn = MySQLdb.connect(**self.mysql_opts)
        self.cursor = self.conn.cursor()
        return self.cursor
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.commit()
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            self.conn.close()
            self.conn = None
