# Fireblocks recovery key utility

## Installation

* Please clone the repository:
  * `git clone https://github.com/fireblocks/fireblocks-key-recovery-tool.git`

* cd fireblocks-key-recovery-tool

### Prerequisites

* Backup file `<backup.zip>`
* Private key `<key.pem>`
* Passphrase


## Option 1 - Running in Docker

### Build the utility in docker
* docker build -t fb_recover_key .

### Run the utility in docker
* cd to `<directory containing the backup file and the private key>`
* Run: docker run -it -v "${PWD}:/opt/fb_recover_keys/backup" fb_recover_key:latest bash
* Run: ./fb_recover_keys.py backup/backup.zip backup/key.pem --prv

## Option 2 - Running Locally

### Build the utility locally
* install python 3
* install pip 3
* apt install libsodium-dev libsecp256k1-dev
* run: pip3 install -r requirements.txt

### Run the utility locally
For a sanity test, run:
* ./fb_recover_keys.py `<backup zip file> <RSA recovery private key>`

Do not run the below for production (mainnet) workspaces, unless for actual disaster scenarios. 

For a full recovery, run:
* ./fb_recover_keys.py `<backup zip file> <RSA recovery private key>` --prv

