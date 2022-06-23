import os
import json

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


# gen and save keys to file
def get_key(name='default', dir='store'):
    os.makedirs(dir, exist_ok=True)
    if not os.path.isfile(os.path.join(dir, f'{name}.pem')):
        key = DSA.generate(1024)
        with open(os.path.join(dir, f'{name}.pub.pem'), 'wb') as f:
            f.write(key.publickey().export_key())
        with open(os.path.join(dir, f'{name}.pem'), 'wb') as f:
            f.write(key.export_key())
        return key.export_key().decode('ascii')
    else:
        with open(os.path.join(dir, f'{name}.pem'), 'r') as f:
            return f.read()

def get_pub_key(name='default', dir='store'):
    return DSA.import_key(get_key(name=name, dir=dir)).publickey().export_key().decode('ascii')

def sign(data, name='default', dir='store', encoding='ascii'):
    print(f"SIGNING PAYLOAD: {json.dumps(data, sort_keys=True)}")
    hash_obj = SHA256.new(json.dumps(data, sort_keys=True).encode(encoding))
    signer = DSS.new(DSA.import_key(get_key(name=name, dir=dir)), 'fips-186-3')
    return signer.sign(hash_obj).hex()

def verify(data, signature, name='default', dir='store', encoding='ascii'):
    return verify_with(get_key(name=name, dir=dir), data, signature, encoding=encoding)

def verify_with(pubkey, data, signature, encoding='ascii'):
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
        print(f"PAYLOAD TO VERIFY: {data}")
    key_obj = DSA.import_key(pubkey.encode(encoding))
    verifier = DSS.new(key_obj, 'fips-186-3')
    hash_obj = SHA256.new(data.encode(encoding))
    try:
        verifier.verify(hash_obj, bytes.fromhex(signature))
        return True
    except ValueError:
        return False
    
def hash_str(data, encoding='ascii'):
    return SHA256.new(data.encode(encoding)).hexdigest()

if __name__ == '__main__':
    # here we create example transaction that can be POST-ed to blockchain
    txn = {
        'data': {
            # 'block_index': db.get_chain_len(),
            'src': hash_str(get_pub_key(name='default')),
            'dst': 'put_address_here',
            'amount': 100
        }
    }
    print(f'txn:         {json.dumps(txn)}')
    txn['signature'] = sign(json.dumps(txn['data'], sort_keys=True), name='default')
    txn['pub_key'] = get_pub_key(name='default')
    with open('txn.json', 'w') as f:
        f.write(json.dumps(txn, sort_keys=True, indent=2))
    
    # verifying transaction
    print(f"signature:   {txn['signature']}")
    print(f"verified:    {verify(json.dumps(txn['data'], sort_keys=True), txn['signature'], name='default')}")
