#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from utils import recover
import getpass
import json
from termcolor import colored

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--shard', help='the path of the shard to be computed')
    parser.add_argument('--mobile', default = False, help='flag for computing mobile shard, default is false')
    parser.add_argument('--metadata', help='path to metadata file')
    parser.add_argument('--priv', help='path to private key file, required for cloud shares only')

    args = parser.parse_args()
    shard_path = args.shard
    metadata_path = args.metadata
    priv_path = args.priv

    id_data = dict(recover.retrieve_identities("./test/backup.zip"))

    try:
        if(args.mobile):
            passphrase = getpass.getpass(prompt='Please enter mobile recovery RSA private key passphrase:')
            output = recover.compute_individual_shard(shard_path, id_data, "Mobile", metadata_path, None, None, passphrase)
            print(json.dumps(output, indent=2))
        else:
            output = recover.compute_individual_shard(shard_path, id_data, "Cloud", metadata_path, priv_path)
            print(json.dumps(output, indent=2))
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

if __name__ == "__main__" :
    main()
