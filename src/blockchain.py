import hashlib
import json
import random
import db

from datetime import datetime
from time import time, sleep
from urllib.parse import urlparse
from uuid import uuid4
from keystore import hash_str, get_key, sign, verify_with

import textwrap
import requests
from flask import Flask, jsonify, request, render_template


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='0' * 64, nonce=0)

    @property
    def last_block(self):
        """
        Last block persisted in database
        """
        return db.get_last_block()
    
    @property
    def last_block_id(self):
        """
        Last mined block's ID
        """
        return self.last_block['id']
    
    @property
    def current_id(self):
        """
        ID for next block in chain
        """
        return self.last_block_id + 1
    
    @property
    def chain_length(self):
        return db.get_chain_len()
    
    def new_block(self, nonce, previous_hash):
        """
        Create a new Block in the Blockchain

        :param nonce: The nonce given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'timestamp': datetime.now(),
            'transactions': self.current_transactions,
            'nonce': nonce,
            'miner_dst': node_identifier,
            'previous_hash': previous_hash or self.hash(db.get_last_block()),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        db.add_block(block)
        return block

    def new_transaction(self, txn_dict):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount
        :return: The index of the Block that will hold this transaction
        """
        txn_dict['timestamp'] = datetime.now()
        self.current_transactions.append(txn_dict)

        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """
        if block == None:
            return None

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        block_hash = hashlib.sha256(block_string).hexdigest()
        print(f'Block:      {block_string}')
        print(f'Block hash: {block_hash}')
        return block_hash

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous nonce, and p' is the new nonce
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_nonce = last_block['nonce']
        last_hash = self.hash(last_block)
        nonce = 0

        while True:
            start = time()
            print(f'trying nonce {nonce}')
            if self.valid_nonce(last_nonce, nonce, last_hash):
                print(self.chain)
                break
            else:
                nonce += 1
                end = time()
                to_sleep = 0.01 - (end - start)
                if to_sleep > 0:
                    sleep(to_sleep)

        return nonce

    @staticmethod
    def valid_nonce(last_nonce, nonce, last_hash):
        """
        Validates the nonce

        :param last_nonce: <int> Previous nonce
        :param nonce: <int> Current nonce
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """
        last_nonce = last_nonce if last_nonce != None else 0
        
        guess = f'{last_hash}{last_nonce}{nonce}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:2] == "00"

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    # USED ONLY WHEN SYNCING...
    # TODO: optimise method:
    #       instead of downloading whole peer blockchain,
    #       we should only iterate from tail backwards
    #       requesting until we find same histories in blockchain
    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_nonce(last_block['nonce'], block['nonce'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        peers = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in peers:
            # In case peer doesn't answer or refuses connection,
            # we ignore him
            response = None
            try:
                response = requests.get(f'http://{node}/chain')
                response.raise_for_status()
            except:
                print(f'Peer {node} didn\'t respond')
                pass

            if response and response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False


# Instantiate the Node
app = Flask(__name__)

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next nonce...
    last_block = blockchain.last_block
    nonce = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the nonce
    blockchain.new_transaction({
        'data': {
            'src': None,
            'dst': node_identifier,
            'amount': 1000
        },
        'signature': None,
        'pub_key': None
    })

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block': block
    }
    return jsonify(response), 200

# generates next transaction
@app.route('/block_id', methods=['GET'])
def current_block_id():
    return jsonify(blockchain.current_id), 200

@app.route('/txn', methods=['POST'])
def new_transaction():
    body = request.get_json()

    # Checking transaction validity
    if not all(k in body for k in ['data', 'signature', 'pub_key']):
        return jsonify({'message': 'Invalid transaction format'}), 400
    if not all(k in body['data'] for k in ['src', 'dst', 'amount', 'block_index']):
        return jsonify({'message': 'Unsupported transaction payload'}), 400
    if not body['data']['block_index'] == blockchain.current_id:
        return jsonify({'message': 'Block index missmatch'}), 400
    if any(x['signature'] == body['signature'] for x in blockchain.current_transactions):
        return jsonify({'message': 'Transaction already recorded for current block'}), 400
    if not hash_str(body['pub_key']) == body['data']['src']:
        return jsonify({'message': 'Source address does not match the hash of pub_key'}), 400
    if not verify_with(body['pub_key'], body['data'], body['signature']):
        return jsonify({'message': 'Transaction signature invalid.'}), 400
    
    # getting account balance from database
    account_balance = db.get_balance(body['data']['src'])['balance']
    # adding possible current block transactions
    # related to this account
    for txn in blockchain.current_transactions:
        if body['src'] == txn['src']:
            account_balance -= txn['amount']
        if body['src'] == txn['dst']:
            account_balance += txn['amount']

    if account_balance < body['data']['amount']:
        return jsonify({'message': 'Not enough funds on account'}), 400

    
    # TODO: save pub_key to database and associate it with address
    #       if it is not already saved

    # add to unconfirmed transactions
    index = blockchain.new_transaction({
        'src': body['data']['src'],
        'dst': body['data']['dst'],
        'amount': body['data']['amount'],
        'signature': body['signature']
    })

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/txn', methods=['GET'])
def list_unconfirmed_txns():
    return jsonify({ 'unconfirmed_txns': list(blockchain.current_transactions) }), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/peer', methods=['GET'])
def list_nodes():
    return jsonify({ 'connected_peers' : list(blockchain.nodes) }), 200


@app.route('/peer', methods=['DELETE'])
def remove_peers():
    blockchain.nodes = blockchain.nodes - set(request.get_json()['nodes'])
    return jsonify({ 'connected_peers': list(blockchain.nodes) }), 200


@app.route('/peer', methods=['POST'])
def new_node():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/sync', methods=['GET'])
def reach_consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-k', '--key', required=True, type=str, help='key to be used by node')
    parser.add_argument('-d', '--database', type=str, help='name of database')
    args = parser.parse_args()

    # initializing database on disk
    db.reinit_db()

    # computed as hex decoded SHA256 hash of fips-186-3 DSS public key exported in string PEM format
    node_identifier = hash_str(get_key(name=args.key))
    print(f'NODE_ID: {node_identifier}')

    # Instantiate the Blockchain
    blockchain = Blockchain()

    app.run(host='0.0.0.0', port=args.port)
