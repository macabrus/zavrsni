import os

from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


# gen and save keys to file
def get_key(name='default', dir='store'):
    os.makedirs(dir, exist_ok=True)
    if not os.path.isfile(os.path.join(dir, f'{name}.pub.pem')):
        key = DSA.generate(1024)
        with open(os.path.join(dir, f'{name}.pub.pem'), 'wb') as f:
            f.write(key.publickey().export_key())
        with open(os.path.join(dir, f'{name}.pem'), 'wb') as f:
            f.write(key.export_key())
        return key
    else:
        with open(os.path.join(dir, f'{name}.pem'), 'r') as f:
            return DSA.import_key(f.read())

def sign(data, name='default', dir='store', encoding='ascii'):
    hash_obj = SHA256.new(data.encode(encoding))
    signer = DSS.new(get_key(name=name, dir=dir), 'fips-186-3')
    return signer.sign(hash_obj).hex()

def verify(data, signature, name='default', dir='store', encoding='ascii'):
    hash_obj = SHA256.new(data.encode(encoding))
    verifier = DSS.new(get_key(name=name, dir=dir), 'fips-186-3')
    try:
        verifier.verify(hash_obj, bytes.fromhex(signature))
        return True
    except ValueError:
        return False

def hash_key(key):
    return SHA256.new(key.publickey().export_key()).hexdigest()

def hash_str(data, encoding='ascii'):
    return SHA256.new(data.encode(encoding)).hexdigest()

if __name__ == '__main__':
    pair = get_key(name='test')
    signature = sign('hello', name='two')
    print(f"key hash:  {hash_key(get_key(name='test'))}")
    print(f'signature: {signature}')
    print(verify('hello', signature, name='two'))
