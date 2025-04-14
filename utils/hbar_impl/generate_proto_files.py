#!/usr/bin/python3

import os
import shutil

FILES = ["proto/" + file for file in os.listdir(os.environ["PWD"] + "/proto/")]
os.system("python3 -m grpc_tools.protoc --proto_path=proto --python_out=gen --grpc_python_out=gen " + " ".join(FILES))