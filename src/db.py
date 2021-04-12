import sqlite3
import json
from datetime import datetime, timedelta

from keystore import hash_str


DB_NAME = 'chain.db'

# name -> value | row mapping factory
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

# connection factory
def conn():
    c = sqlite3.connect(DB_NAME)
    c.row_factory = dict_factory
    return c

def init_db():
    with conn() as db:
        db.execute('''
        CREATE TABLE IF NOT EXISTS block (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME,
            nonce INTEGER,
            previous_hash VARCHAR(64),
            miner_dst VARCHAR(64)
        )''')
        db.execute('''
        CREATE TABLE IF NOT EXISTS txn (
            block_id INTEGER,
            timestamp DATETIME,
            src VARCHAR(64),
            dst VARCHAR(64),
            amount INT,
            signature TEXT,
            FOREIGN KEY (block_id) REFERENCES block(id)
        )''')
        db.execute('''
        CREATE TABLE IF NOT EXISTS address (
            pubkey TEXT,
            address VARCHAR(64)
        )''')


def reinit_db():
    with conn() as db:
        db.execute('DROP TABLE IF EXISTS block')
        db.execute('DROP TABLE IF EXISTS txn')
        db.execute('DROP TABLE IF EXISTS address')
    init_db()

def get_pubkey(address):
   with conn() as db:
       return db.execute('SELECT * FROM address WHERE address = ?', (address,)).fetchone()

def add_address(pubkey_pem):
    # hash a pubkey and that's the address
    address = hash_str(pubkey_pem)
    with conn() as db:
        db.execute('INSERT INTO address VALUES (?, ?)', (pubkey_pem, address))

# records mined block into blockchain on disk
def add_block(block):
    block_id = get_chain_len()
    with conn() as db:
        timestamp    = block['timestamp']
        nonce        = block['nonce']
        prev_hash    = block['previous_hash']
        miner_dst    = block['miner_dst']
        db.execute(
            'INSERT INTO block VALUES (?, ?, ?, ?, ?)',
            (block_id, timestamp, nonce, prev_hash, miner_dst)
        )
        for t in block['transactions']:
            db.execute(
                'INSERT INTO txn VALUES (?, ?, ?, ?, ?, ?)', 
                (block_id, t['timestamp'], t['src'], t['dst'], t['amount'], t['signature'])
            )
    return block_id

def get_block(id):
    with conn() as db:
        block_info = db.execute(
            'SELECT * FROM block WHERE id = ?',
            (id, )
        ).fetchone()
        txns = db.execute(
            'SELECT * FROM txn WHERE block_id = ?',
            (id, )
        ).fetchall()
        block_info['transactions'] = txns
        return block_info

def get_last_block():
    with conn() as db:
        res = db.execute('SELECT MAX(id) as id FROM block').fetchone()
    return get_block(res['id']) if res['id'] != None else None

def get_chain_len():
    with conn() as db:
        return db.execute('SELECT COUNT(*) as len FROM block').fetchone()['len']

def get_balance(address):
    with conn() as db:
        res = db.execute('''
        SELECT SUM(
            CASE
                WHEN src = ? AND dst = ? THEN 0
                WHEN src = ? THEN -amount
                WHEN dst = ? THEN amount
                ELSE 0
            END
        ) as balance
        FROM txn
        ''', (address, address, address, address)
        ).fetchone()
        res['address'] = address
        return res

if __name__ == '__main__':
    reinit_db()

    a = hash_str('a')
    b = hash_str('b')
    c = hash_str('c')
    d = hash_str('d')

    block1 = hash_str('block1')
    block2 = hash_str('block2')
    block3 = hash_str('block3')

    block = {
        'timestamp': datetime.now(),
        'nonce': 73485,
        'previous_hash': block1,
        'miner_dst': a,
        'transactions': [{ # self given block reward
            'timestamp': datetime.now(),
            'src': None,
            'dst': a,
            'amount': 1000, # depending on consenzus, it can change or be fixed
            'signature': 'todo'
        }, { # other transactions...
            'timestamp': datetime.now() + timedelta(hours=1),
            'src': a,
            'dst': b,
            'amount': 100,
            'signature': 'todo'
        }, {
            'timestamp': datetime.now() + timedelta(hours=2),
            'src': b,
            'dst': c,
            'amount': 50,
            'signature': 'todo'
        }, {
            'timestamp': datetime.now() + timedelta(hours=3),
            'src': b,
            'dst': d,
            'amount': 10,
            'signature': 'todo'
        }]
    }

    id1 = add_block(block)
    id2 = add_block(block)

    print(get_balance(a))
    print(get_balance(b))
    print(get_balance(c))
    print(get_balance(d))
    print(f'chain length {get_chain_len()}')
    print(f'last block id {get_last_block()["id"]}')
    # print(get_txn())

