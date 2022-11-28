# import pytest
import sys
import json

sys.path.append("..")
from utils import recover

if __name__ == '__main__':
    id_data = dict(recover.retrieve_identities("backup.zip"))
    print("Retrieved identities", json.dumps(id_data, indent=2))
    recover.extract_backup_contents("backup.zip")
    print("Extracted backup file contents to current directory")
    
    output = recover.compute_individual_shard("MOBILE_067681f4-3ae7-eda5-9ab7-4a3cc96c110a",id_data,"Mobile","metadata.json", None, None, "Thefireblocks1!")
    print(json.dumps(output, indent=2))
    
    output = recover.compute_individual_shard("3429798433_067681f4-3ae7-eda5-9ab7-4a3cc96c110a",id_data,"Cloud","metadata.json","priv.pem")
    print(json.dumps(output, indent=2))
    
    output = recover.compute_individual_shard("923242535_067681f4-3ae7-eda5-9ab7-4a3cc96c110a",id_data,"Cloud","metadata.json", "priv.pem")
    print(json.dumps(output, indent=2))
   
