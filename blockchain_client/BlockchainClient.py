from random import random

from flask import Flask, render_template, request, redirect, jsonify
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA



class Transaction:
    def __init__(self, sender_public_key, sender_private_key,
                 recipient_public_key, amount):
        # current custodian public key (officer/lab handing over evidence)
        self.sender_public_key = sender_public_key
        # current custodian private key (used to sign the custody record)
        self.sender_private_key = sender_private_key
        # new custodian public key (who will receive the evidence)
        self.recipient_public_key = recipient_public_key
        # In our use case, 'amount' is actually an EVIDENCE DETAILS string.
        # Example: "CASE123-DRIVE01, seized from suspect PC, sent to forensic lab"
        self.amount = amount

    def to_dict(self):
        # This structure must match what the blockchain node expects.
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount
        })

    def sign_transaction(self):
        
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


app = Flask(__name__)


@app.route('/')
def index():
    # Wallet / identity generator page (Officer / Lab / Prosecutor identities)
    return render_template('index.html')


@app.route('/make/transaction')
def make_transaction():
    # Page for creating a new custody event (evidence transfer)
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    # Page for viewing custody records from the blockchain node
    return render_template('view_transactions.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    # Here 'amount' is actually EVIDENCE DETAILS (ID, description, purpose).
    amount = request.form['amount']

    transaction = Transaction(sender_public_key,
                              sender_private_key,
                              recipient_public_key,
                              amount)

    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.sign_transaction()
    }
    return jsonify(response), 200


@app.route('/wallet/new')
def new_wallet():
    
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format('DER'))).decode('ascii')
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    # This client only serves the local browser
    app.run(host='0.0.0.0', port=port, debug=True)
