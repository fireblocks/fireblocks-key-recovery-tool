#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from utils import recover
import argparse
import getpass

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('backup', help='Backup zip file')
    parser.add_argument('key', help='RSA key file')
    parser.add_argument('--prv', '-p', default=False,
                        action='store_const', const=True,
                        help='Reveal private key')
    args = parser.parse_args()

    if not os.path.exists(args.backup):
        print('Backupfile: {} not found'.format(args.backup))
        exit(- 1)
    if not os.path.exists(args.key):
        print('RSA key: {} not found'.format(args.key))
        exit(-1)
    
    passphrase = getpass.getpass(prompt='Please enter user recovery passphrase:')

    privkey, chaincode = recover.restore_key_and_chaincode(
        args.backup, args.key, passphrase)

    if (not chaincode or len(chaincode) != 32):
        print("ERROR: metadata.json doesn't contain valid chain code")
        exit(-1)

    pub = recover.get_public_key(privkey)

    if args.prv:
        print("expriv:\t" + recover.encode_extended_key(privkey, chaincode, False))
        
    print("expub:\t" + recover.encode_extended_key(pub, chaincode, True))

if __name__ == "__main__" :
    main()
