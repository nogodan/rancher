#########################################################################
# This script to do
# pull required container images from internet then tag upload to local container repo(such as harbor)
# - images list are in images.txt file in format of
'''
rancher/nginx-ingress-controller:nginx-0.43.0-rancher1
rancher/pause:3.1
rancher/pause:3.2
'''
# Version 1.0  17 Sept 2022 Taeho.Choi
#########################################################################
#!/usr/bin/env python3
import os
import sys

class Constants:
  LOCAL_REPO = "rancher"
  LOCAL_REG = $PRIVATE_REGISTRY_URL
  INPUT_IMAGES_LIST = 'images.txt'
  REPO_ID = $PRIVATE_REGISTRY_LOGIN_ID
  CRED_FILE = $PRIVATE_REGISTRY_LOGIN_PASSWD_FILE_PATH

def doc_cmd(action):
    file = open(Constants.INPUT_IMAGES_LIST, 'r')
    Lines = file.readlines()
    count = 0
    for line in Lines:
        count += 1
        line = line.strip()
        if action == "tag":
            os.system('docker '+action+' '+line+' '+Constants.LOCAL_REG+line)
        elif action == "pull":
            os.system('docker '+action+' '+line)
        elif action == "push":
            os.system('docker '+action+' '+Constants.LOCAL_REG+line)
        else:
            print("Hmm something wrong with the docker verb")

def doc_login():
    _pass = open(Constants.CRED_FILE,'r').readlines()
    return os.system('docker login '+ Constants.LOCAL_REG + Constants.LOCAL_REPO +' -u '+ Constants.REPO_ID + ' -p '+ _pass[0])

def main():
    #pulling docker images to local dir
    doc_cmd('pull')
    doc_login()
    doc_cmd('tag')
    doc_cmd('push')

if __name__ == "__main__":
    sys.exit(main())
