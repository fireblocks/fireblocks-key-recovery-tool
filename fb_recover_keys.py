#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from utils import recover
import argparse
import getpass
import sys
from termcolor import colored

pubkey_descriptions = {
    'MPC_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPUB',
    'MPC_CMP_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPUB',
    'MPC_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended public key (Fireblocks format)',
    'MPC_CMP_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended public key (Fireblocks format)',
}

privkey_descriptions = {
    'MPC_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPRV',
    'MPC_CMP_ECDSA_SECP256K1': 'MPC_ECDSA_SECP256K1 XPRV',
    'MPC_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended private key (Fireblocks format)',
    'MPC_CMP_EDDSA_ED25519': 'MPC_EdDSA_ED25519 extended private key (Fireblocks format)',
}


def query_yes_no(question, default="yes"):
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('backup', help='Backup zip file')
    parser.add_argument('key', help='RSA private key file')
    parser.add_argument('--prv', default=False,
                        action='store_const', const=True,
                        help='Reveal private key')
    parser.add_argument('--mobile-key', help='mobile RSA private key file', default=None)
    args = parser.parse_args()

    if not os.path.exists(args.backup):
        print('Backupfile: {} not found.'.format(args.backup))
        exit(- 1)
    if not os.path.exists(args.key):
        print('RSA key: {} not found.'.format(args.key))
        exit(-1)
    
    mobile_key_pass = None
    passphrase = None

    if args.mobile_key is None:
        passphrase = getpass.getpass(prompt='Please enter mobile recovery passphrase:')
    else:
        with open(args.mobile_key, 'r') as _key:
            if 'ENCRYPTED' in _key.readlines()[1]:
                mobile_key_pass = getpass.getpass(prompt='Please enter mobile recovery RSA private key passphrase:')

    with open(args.key, 'r') as _key:
        if 'ENCRYPTED' in _key.readlines()[1]:
            key_pass = getpass.getpass(prompt='Please enter recovery RSA private key passphrase:')
        else:
            key_pass = None

    try:
        privkeys, chaincode = recover.restore_key_and_chaincode(
            args.backup, args.key, passphrase, key_pass, args.mobile_key, mobile_key_pass)
    except recover.RecoveryErrorMobileKeyDecrypt:
        print(colored("Failed to decrypt mobile Key. " + colored("Please make sure you have the mobile passphrase entered correctly.", attrs = ["bold"]), "cyan")) 
        exit(-1)
    except recover.RecoveryErrorRSAKeyImport:
        print(colored("Failed to import RSA Key. " + colored("Please make sure you have the RSA passphrase entered correctly.", attrs = ["bold"]), "cyan")) 
        exit(-1)
    except recover.RecoveryErrorMobileRSAKeyImport:
        print(colored("Failed to import mobile RSA Key. " + colored("Please make sure you have the RSA passphrase entered correctly.", attrs = ["bold"]), "cyan")) 
        exit(-1)
    except recover.RecoveryErrorMobileRSADecrypt:
        print(colored("Failed to decrypt mobile Key. " + colored("Please make sure you have the mobile private key entered correctly.", attrs = ["bold"]), "cyan")) 
        exit(-1)

    if (not chaincode or len(chaincode) != 32):
        print(colored("metadata.json doesn't contain a valid chain code.", "cyan"))
        exit(-1)

    show_xprv = False
    if args.prv:
        show_xprv = query_yes_no('''
Are you sure you want to show the extended private key of the Vault?
Be sure you are in a private location and no one can see your screen.'''
        , default = "no")

    for algo, privkey in privkeys.items():
        if privkey:
            pub = recover.get_public_key(algo, privkey)
            if show_xprv:
                print(privkey_descriptions[algo] + ":\t" + recover.encode_extended_key(algo, privkey, chaincode, False))
            print(pubkey_descriptions[algo] + ":\t%s\t%s" % (recover.encode_extended_key(algo, pub, chaincode, True), colored("Verified!","green")))
        else:
            print(pubkey_descriptions[algo] + ":\t%s" % (colored("Verification failed","red")))

if __name__ == "__main__" :
    main()
