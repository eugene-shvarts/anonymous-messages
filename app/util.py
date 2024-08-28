import json

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

class Config:
    def __init__(self, config_file="config.json"):
        with open(config_file) as f:
            self.config = json.load(f)
    
    def __getitem__(self, key):
        return self.config[key]

    def __contains__(self, key):
        return key in self.config

    def __str__(self):
        return str(self.config)

    def __repr__(self):
        return repr(self.config)
