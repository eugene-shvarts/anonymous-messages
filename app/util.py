import os

import MySQLdb, sshtunnel

from constants import LOCAL_SSH_TUNNEL_PORT, MYSQL_PORT

sshtunnel.SSH_TIMEOUT = 5.0
sshtunnel.TUNNEL_TIMEOUT = 5.0

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
        self.mysql_config = mysql_config
        self.conn = None
        self.cursor = None

    def __enter__(self):
        self.conn = MySQLdb.connect(**self.mysql_config)
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

class ConnectionSSHContext:
    def __init__(self, mysql_config):
        self.mysql_config = mysql_config
        self.ssh_host = os.environ.get('SSH_HOST')
        self.tunnel_config = {
            'ssh_username': os.environ.get('SSH_USER'),
            'ssh_password': os.environ.get('SSH_PASSWORD'),
            'local_bind_address': ('127.0.0.1', LOCAL_SSH_TUNNEL_PORT),
            'remote_bind_address': (os.environ.get('MYSQL_DB_HOST'), MYSQL_PORT)
        }
        self.tunnel = None
        self.conn = None
        self.cursor = None

    def __enter__(self):
        self.tunnel = sshtunnel.open_tunnel(self.ssh_host, **self.tunnel_config)
        self.tunnel.start()
        self.conn = MySQLdb.connect(**self.mysql_config)
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
        if self.tunnel:
            self.tunnel.close()
            self.tunnel = None
