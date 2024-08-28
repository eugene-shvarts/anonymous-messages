from itertools import chain
import json, os, sys
from os.path import abspath, dirname, join

app_dir = abspath(join(dirname(abspath(__file__)), '..', 'app'))
sys.path.append(app_dir)

import requests

from constants import MYSQL_PORT
from model import Person
from util import ConnectionContext


connctx = ConnectionContext({
    'user': os.environ.get('MYSQL_DB_USER'),
    'password': os.environ.get('MYSQL_DB_PASSWORD'),
    'db': os.environ.get('MYSQL_DB_DATABASE'),
    'host': os.environ.get('MYSQL_DB_HOST'),
    'port': MYSQL_PORT
})

### sets up the database with the correct schema, and some default questions
questions = [
    (
        "favorite_memory",
        "What's your favorite memory of me?"
    ),
    (
        "lasting_impact",
        "What's a lasting impact I've left on you?"
    ),
    (
        "shared_activity",
        "What's an activity you'd want to do with me?"
    ),
    (
        "anything_else",
        "Anything else you want me to know?"
    )
]

question_stmt = """CREATE TABLE IF NOT EXISTS `questions` (
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `text` TEXT,
    `label` VARCHAR(50)
)"""

persons_stmt = """CREATE TABLE IF NOT EXISTS `persons` (
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(50),
    `fullname` VARCHAR(100) NOT NULL,
    `secret_key_hash` VARCHAR(60) NOT NULL,
    `encrypted_private_key` TEXT NOT NULL,
    `public_key` TEXT NOT NULL
)"""

responses_stmt = """CREATE TABLE IF NOT EXISTS `responses` (
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `question_id` INT NOT NULL,
    `group_id` INT NOT NULL,
    `person_id` INT NOT NULL,
    `encrypted_text` TEXT
)"""

with connctx as conn:
    conn.execute(question_stmt)
    conn.execute(persons_stmt)
    conn.execute(responses_stmt)
    conn.execute(
        f'INSERT INTO questions (label, text) VALUES {", ".join(["(%s, %s)"] * len(questions))}',
        chain.from_iterable(questions)
    )

### creates a config file from the example file if needed
if not os.path.exists(join(app_dir, 'config.json')):
    with open(join(app_dir, 'config.json'), 'w') as dst, open(join(app_dir, 'config.example.json')) as src:
        json.dump(json.load(src), dst)

### initializes a test user
with connctx as conn:
    secret = Person.new(conn, 'testy', 'testy-mctesterson')

with open(join(app_dir, 'static', 'testy-mctesterson.jpg'), 'wb') as f:
    f.write(requests.get('https://thispersondoesnotexist.com').content)

print(f"The secret for the test user is {secret}")
