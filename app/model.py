import os

import bcrypt

from dataclasses import dataclass, fields
from cipher import generate_key_pair, serialize_public_key, encrypt_private_key, secret_from_user_info
from constants import USER_SECRET_KEY_LENGTH

def query_fields(cls):
    return ', '.join(f.name for f in fields(cls))

def insert_fields(cls):
    return ', '.join(f.name for f in fields(cls) if f.name != 'id')

def parameter_markers(cls):
    n = len(fields(cls))
    if 'id' in [f.name for f in fields(cls)]:
        n -= 1
    return ', '.join(['%s'] * n)

@dataclass
class Person:
    name: str
    fullname: str
    public_key: str
    encrypted_private_key: str
    secret_key_hash: str
    id: int = 0

    @classmethod
    def get(cls, conn, id):
        conn.execute(f'SELECT {query_fields(cls)} FROM persons WHERE id = %s', (id,))
        row = conn.fetchone()
        return cls(*row) if row else None
    
    @classmethod
    def get_by_fullname(cls, conn, fullname):
        conn.execute(f'SELECT {query_fields(cls)} FROM persons WHERE fullname = %s', (fullname,))
        row = conn.fetchone()
        return cls(*row) if row else None
    
    def insert(self, conn):
        conn.execute(
            f'INSERT INTO persons ({insert_fields(self)}) VALUES ({parameter_markers(self)})',
            (self.name, self.fullname, self.public_key, self.encrypted_private_key, self.secret_key_hash)
        )

    # creates a new user, and returns the secret key used to generate that user; equivalent to user_id and password
    @classmethod
    def new(cls, conn, name, fullname):
        private_key, public_key = generate_key_pair()
        public_key_str = serialize_public_key(public_key)
        
        pw = os.urandom(USER_SECRET_KEY_LENGTH)
        encrypted_private_key = encrypt_private_key(private_key, pw)
        secret_key_hash = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()

        cls(name, fullname, public_key_str, encrypted_private_key, secret_key_hash).insert(conn)
        return secret_from_user_info(conn.lastrowid, pw)

@dataclass
class Response:
    person_id: int
    question_id: int
    group_id: int
    encrypted_text: str
    id: int = 0

    @classmethod
    def get_by_person(cls, conn, person_id):
        conn.execute(f'SELECT {query_fields(cls)} FROM responses WHERE person_id = %s', (person_id,))
        rows = conn.fetchall()
        return [ cls(*row) for row in rows ]

    @classmethod
    def next_group_id(cls, conn):
        conn.execute('SELECT group_id from responses ORDER BY id DESC LIMIT 1')
        group_id = conn.fetchone()
        return group_id[0] + 1 if group_id else 1

    def insert(self, conn):
        conn.execute(
            f'INSERT INTO responses ({insert_fields(self)}) VALUES ({parameter_markers(self)})',
            (self.person_id, self.question_id, self.group_id, self.encrypted_text)
        )

@dataclass
class Question:
    label: str
    text: str
    id: int = 0

    @classmethod
    def get_all(cls, conn):
        conn.execute(f'SELECT {query_fields(cls)} FROM questions')
        rows = conn.fetchall()
        return [ cls(*row) for row in rows ]

    def insert(self, conn):
        conn.execute(
            f'INSERT INTO questions ({insert_fields(self)}) VALUES ({parameter_markers(self)})',
            (self.label, self.text)
        )

    @property
    def placeholder(self):
        return ''
