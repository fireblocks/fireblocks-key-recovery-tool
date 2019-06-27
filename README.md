# Fireblocks recovery key utility

## Installation

* Please clone the repository:
  * `git clone https://github.com/fireblocks/fb_recover_keys.git`

## Build the utility

### Build the utility in docker

* docker build -t fb_recovery_key .

### Build the utility locally

* install python 3
* install pip 3
* run: pip3 install -r requirements.txt

## Running the utility

### Prerequisites

* Backup file `<backup.zip>`
* Private key `<key.pem>`
* Passphrase

#### Run the utility in docker

* cd to `<directory containing the backup file and the private key>`
* Run: docker run -it -v "${PWD}:/opt/fb_recover_keys/backup" fb_recovery_key:latest bash
* Run: ./fb_recover_keys.py backup/backup.zip backup/key.pem --prv

#### Run the utility locally

* ./fb_recover_keys.py `<backup file> <private key>` --prv
