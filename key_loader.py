import csv
import base64
import random
import os
from Crypto.PublicKey import RSA, ECC

def load_keys_from_csv(enc_filename='encryption_keys.csv', dec_filename='decryption_keys.csv'):
    encryption_key_sets = []
    decryption_key_sets = []
    
    try:
        # Load encryption keys
        with open(enc_filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                encryption_key_sets.append(row)
        
        # Load decryption keys
        with open(dec_filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                decryption_key_sets.append(row)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {e.filename}")
    except Exception as e:
        raise Exception(f"Error loading keys from CSV: {e}")
    
    return encryption_key_sets, decryption_key_sets

def select_random_key_set(encryption_key_sets, decryption_key_sets):
    if not encryption_key_sets or not decryption_key_sets:
        raise ValueError("No key sets available")
    
    random_index = random.randint(0, min(len(encryption_key_sets), len(decryption_key_sets)) - 1)
    
    return encryption_key_sets[random_index], decryption_key_sets[random_index], random_index

def prepare_keys(enc_key_set, dec_key_set):
    try:
        # Decode base64 keys
        key_aes = base64.b64decode(enc_key_set['aes_key'])
        key_des = base64.b64decode(enc_key_set['des_key'])
        key_tdes = base64.b64decode(enc_key_set['tdes_key'])
        
        # Import RSA keys
        private_key_rsa_data = base64.b64decode(dec_key_set['private_key_rsa'])
        private_key_rsa = RSA.import_key(private_key_rsa_data)
        
        public_key_rsa_data = base64.b64decode(enc_key_set['public_key_rsa'])
        public_key_rsa = RSA.import_key(public_key_rsa_data)
        
        # Import ECC keys
        private_key_ecc_d = int(base64.b64decode(dec_key_set['private_key_ecc']).decode())
        
        public_key_ecc_data = base64.b64decode(enc_key_set['public_key_ecc']).decode().split('|')
        public_key_ecc_x = int(public_key_ecc_data[0])
        public_key_ecc_y = int(public_key_ecc_data[1])
        
        # Construct ECC keys
        private_key_ecc = ECC.construct(curve='P-256', d=private_key_ecc_d)
        public_key_ecc = ECC.construct(curve='P-256', point_x=public_key_ecc_x, point_y=public_key_ecc_y)
    except (ValueError, KeyError, TypeError) as e:
        raise ValueError(f"Error preparing keys: {e}")
    
    return key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc

def get_random_keys():
    enc_filename = 'encryption_keys.csv'
    dec_filename = 'decryption_keys.csv'
    
    if not os.path.exists(enc_filename) or not os.path.exists(dec_filename):
        print(f"Keys files not found. Generating new keys...")
        from generate_keys import generate_keys_csv
        generate_keys_csv(num_sets=20, enc_filename=enc_filename, dec_filename=dec_filename)
    
    encryption_key_sets, decryption_key_sets = load_keys_from_csv(enc_filename, dec_filename)
    print(f"Loaded {len(encryption_key_sets)} encryption key sets and {len(decryption_key_sets)} decryption key sets")
    
    enc_key_set, dec_key_set, random_index = select_random_key_set(encryption_key_sets, decryption_key_sets)
    print(f"\nRandomly selected key set")
    
    return prepare_keys(enc_key_set, dec_key_set), random_index

def get_keys_by_index(index, enc_filename='encryption_keys.csv', dec_filename='decryption_keys.csv'):
    encryption_key_sets, decryption_key_sets = load_keys_from_csv(enc_filename, dec_filename)
    
    if index < 0 or index >= len(encryption_key_sets) or index >= len(decryption_key_sets):
        raise IndexError("Index out of range")
    
    enc_key_set = encryption_key_sets[index]
    dec_key_set = decryption_key_sets[index]
    
    try:
        # Decode base64 keys
        key_aes = base64.b64decode(enc_key_set['aes_key'])
        key_des = base64.b64decode(enc_key_set['des_key'])
        key_tdes = base64.b64decode(enc_key_set['tdes_key'])
        
        # Import RSA keys
        private_key_rsa_data = base64.b64decode(dec_key_set['private_key_rsa'])
        private_key_rsa = RSA.import_key(private_key_rsa_data)
        
        public_key_rsa_data = base64.b64decode(enc_key_set['public_key_rsa'])
        public_key_rsa = RSA.import_key(public_key_rsa_data)
        
        # Import ECC keys
        private_key_ecc_d = int(base64.b64decode(dec_key_set['private_key_ecc']).decode())
        
        public_key_ecc_data = base64.b64decode(enc_key_set['public_key_ecc']).decode().split('|')
        public_key_ecc_x = int(public_key_ecc_data[0])
        public_key_ecc_y = int(public_key_ecc_data[1])
        
        # Construct ECC keys
        private_key_ecc = ECC.construct(curve='P-256', d=private_key_ecc_d)
        public_key_ecc = ECC.construct(curve='P-256', point_x=public_key_ecc_x, point_y=public_key_ecc_y)
    except (ValueError, KeyError, TypeError) as e:
        raise ValueError(f"Error preparing keys: {e}")
    
    return key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc

# Example usage
if __name__ == "__main__":
    index = 0  # Replace with the desired index
    try:
        keys = get_keys_by_index(index)
        print("Keys at index", index, ":", keys)
    except Exception as e:
        print("Error:", e)