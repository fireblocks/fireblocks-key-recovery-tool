# Fireblocks recovery key utility

## Installation

* Please clone the repository:
  * `git clone https://github.com/fireblocks/fb_recover_keys.git`

* cd fb_recover_keys

### Prerequisites

* Backup file `<backup.zip>`
* Private key `<key.pem>`
* Passphrase


## Running in Docker

### Build the utility in docker
* docker build -t fb_recover_key .

### Run the utility in docker
* cd to `<directory containing the backup file and the private key>`
* Run: docker run -it -v "${PWD}:/opt/fb_recover_keys/backup" fb_recover_key:latest bash
* Run: ./fb_recover_keys.py backup/backup.zip backup/key.pem --prv

## Running Locally

### Build the utility locally
* install python 3
* install pip 3
* run: pip3 install -r requirements.txt

### Run the utility locally
* ./fb_recover_keys.py `<backup zip file> <RSA recovery private key>` --prv
