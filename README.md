# Fireblocks Key Backup and Recovery Tool

The Fireblocks Backup and Recovery Tool simplifies completing four important backup and recovery actions for your Fireblocks workspace keys. You should use this tool on a designated offline machine.  
Follow the steps to [create a Workspace Keys Backup file](https://support.fireblocks.io/hc/en-us/articles/360012223159-Workspace-Keys-Backup-and-Recovery-Hard-Key-Recovery-).  
Your Owner must have their Owner recovery passphrase.  

## Installation

* Please clone the repository:
  * `git clone https://github.com/fireblocks/fireblocks-key-recovery-tool.git`

* `cd fireblocks-key-recovery-tool`


## Running in Docker

### Build
* `docker build -t fb_recover_key .`

### Run
* cd to `<directory containing the backup file and the private key>`
* Run: `docker run -it -v "${PWD}:/opt/fb_recover_keys/backup" fb_recover_key:latest bash`
* See below for instructions on how to run the recovery tool.

## Running Locally

### Build
* `install python 3.9`
* `install pip3`
* `pip3 install -r requirements.txt`

## Running the Fireblocks Key Backup and Recovery Tool
  1. Recommended: 
      * run `./fireblocks_key_backup_and_recovery.py`

      #### It opens a menu with the following options:
      1. **Create a recovery key pair** - generate a recovery key-pair. You will be required to
      create a key pair passphrase to encrypt the private key file from the key pair.
      2. **Verify the public backup key** - verify the public key file of the recovery key-pair. 
      This is useful for users with Self-Serve backups who want to validate that their workspace 
      Owner’s request to back up the keys matches the key pair at their premise. Requires the 
      recovery key-pair public key.
      3. **Verify the recovery package** - run a sanity test of the workspace key backup package. 
      Requires: the backup package, the recovery key pair private key file, the passphrase to that 
      private  key file, and the owner’s passphrase.
      4. **Reveal the private backup key** - Requires: the backup package, the recovery key pair 
      private key file, the passphrase to that private key file, and the owner’s passphrase.

  2. Use the Legacy script:  `./fb_recover_keys.py`
      * Unlike with the recommended method above, with this method you need to prepare the recovery private key and the backup zip file in advance.  
      * run `./fb_recover_keys.py <backup zip file> <RSA recovery private key>` --prv