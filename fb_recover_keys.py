import sys
import recover

def help():
    msg = """usage: fb_recover_keys.py <<backup zip pathname>> <<rsa key file path>> <<user recovery passphrase>> <options>

Options:
--prv - reveal private key. Otherwise only the public address of the
--help (-h) - print this message    """

    print(msg)

def main():
    if len(sys.argv) < 4:
        help()
        exit(0)
    
    privkey, chaincode = recover.restore_key_and_chaincode(sys.argv[1], sys.argv[2], sys.argv[3])
    
    if (not chaincode or len(chaincode) != 32):
        print("ERROR: metadata.json doesn't contain valid chain code")
        exit(-1)
    
    pub = recover.get_public_key(privkey)

    if "--prv" in sys.argv:
        print("expriv:\t" + recover.encode_extended_key(privkey, chaincode, False))
    print("expub:\t" + recover.encode_extended_key(pub, chaincode, True))

if __name__== "__main__" :
    main()
