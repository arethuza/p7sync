import argparse
import os
import requests

USER_NAME = None
USER_PASSWORD = None
USER_TOKEN = None

def main():
    command, local_dir, url = parse_args()
    if command == "sync":
        sync(local_dir, url)

def parse_args():
    parser = argparse.ArgumentParser(description='Sync using RedSquirrel')
    parser.add_argument("command", help="command to perform: sync")
    parser.add_argument("dir", help="local directory")
    parser.add_argument("--url", help="url of p7 folder")
    parser.add_argument("--user", help="username:password")
    global USER_NAME, USER_PASSWORD
    args = parser.parse_args()
    USER_NAME, USER_PASSWORD = args.user.split(":")
    return args.command, args.dir, args.url

def sync(local_dir, url):
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)
    server_dir_contents = list_server_directory_contents(url)

def get_json(url, params=None):
    get_token(url)
    global USER_TOKEN
    headers={"Authorization": "bearer " + USER_TOKEN}
    # Attempt 1
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 403:
        get_token(url, force_request=True)
        # Attempt 2
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception()
    return response.json

def get_token(url, force_request=False):
    global USER_TOKEN
    if USER_TOKEN and not force_request:
        return
    data = {"name": USER_NAME, "password": USER_PASSWORD}
    response = requests.post(url, data=data)
    if response.status_code == 403:
        raise Exception("Can't log in - supplied url, username or password may be invalid")
    if not "token" in response.json:
        raise Exception("Invalid response from server - no token supplied")
    USER_TOKEN = response.json["token"]

def list_server_directory_contents(url):
    params = {"return_dict": True}
    server_dir_list = get_json(url, params=params)
    pass


if __name__ == '__main__':
    main()


