#########################################################################
# This script will be used to
# - find the latest backup filename that was exported by Rancher main cluster via backup operator
# - update the local restore.yml with a retrieved filename to deploy restore crd in the standby rancher cluster
# Version 1.0  25 Aug 2022 Taeho.Choi
#########################################################################

#!/usr/bin/env python3

from minio import Minio
import os
import sys
import yaml

#Certificate file for MINIO SVC
os.environ['SSL_CERT_FILE'] = './public.crt'

class Constants:
  MINIO_SVR = "$MINIO_URL:PORT"
  ACCESS_KEY = "$MINIO_KEY"
  SECRET_KEY = "$MINIO_SECRETY"
  BUCKET_NAME = "$MINIO_BUCKETNAME"
  RESTORE_YAML = "restore.yml"

def update_yaml(config_yaml,value):
    stream = open(config_yaml,'r')
    data = yaml.safe_load(stream)
    data["spec"]["backupFilename"] = value

    #Writting the config file with new value
    with open(config_yaml, 'w') as updated_f:
        updated_f.write(yaml.dump(data,default_flow_style=False))

def main():
    # Create client with custom HTTP client using proxy server.
    client = Minio(
        Constants.MINIO_SVR,
        access_key=Constants.ACCESS_KEY,
        secret_key=Constants.SECRET_KEY ,
        secure=True,
    )

    objects = client.list_objects(Constants.BUCKET_NAME, recursive=True )
    #sorted object by last_modified time
    sortedobj  = sorted(objects, key=lambda d: d.last_modified)

    #finding the last object name for the latest backup filename
    new_val = sortedobj[-1].object_name
    #Update yaml file with the new value
    update_yaml(Constants.RESTORE_YAML, new_val)

if __name__ == "__main__":
    sys.exit(main())
