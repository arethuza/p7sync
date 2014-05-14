import argparse
import os
import requests
import json
import datetime
import math
import hashlib
import copy
import dateutil

BLOCK_LENGTH=int(math.pow(2, 22))

USER_NAME = None
USER_PASSWORD = None
USER_TOKEN = None

SYNC_FILE_NAME = ".sync.json"

def main():
    command, dir_path, url = parse_args()
    if command == "sync":
        sync(dir_path, url)

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


def sync(dir_path, url):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    previous_dir_state = load_dir_state_file(dir_path, url)
    current_dir_state, local_changes = get_current_dir_state(dir_path, previous_dir_state)
    server_dir_state = get_server_directory_state(url)
    # Calculate actions to be performed on server/locally
    # Perform actions - updating current dir state
    # Write out updated dir state


def get_current_dir_state(dir_path, previous_dir_state):
    local_changes = []
    # Start off with a copy of the previous state
    current_dir_state = copy.copy(previous_dir_state)
    for name, dir_state_entry in previous_dir_state.items():
        path = os.path.join(dir_path, name)
        entry_type = dir_state_entry["type"]
        type_has_changed = ((os.path.isfile(path) and entry_type == "dir") or
                           (os.path.isdir(path) and entry_type == "file"))
        # Delete any entries that have been deleted or changes between file and dir
        if type_has_changed or os.path.exists(path):
            del current_dir_state[name]
            local_changes.append(("delete", name))
    # Look at the contents of the dir
    for name in os.listdir(dir_path):
        if name == SYNC_FILE_NAME:
            continue
        path = os.path.join(dir_path, name)
        if os.path.isfile(path):
            if not name in previous_dir_state:
                # A file has been created
                current_dir_state[name] = create_dir_state_entry(path)
                local_changes.append(("create", name))
            else:
                # A file we have seen before
                previous_modified = dateutil.parser.parse(previous_dir_state[name]["modified"])
                current_modified = get_modified(path)
                if current_modified > previous_modified:
                    update_dir_state_entry(path, current_dir_state[name])
                    local_changes.append(("update", name))
        elif os.path.isdir(path):
            if not name in current_dir_state:
                current_dir_state[name] = {"type": "dir"}
                local_changes.append(("create", name))
    return current_dir_state, local_changes


def create_dir_state_entry(file_path):
    block_hashes = get_block_hashes(file_path)
    return {
        "type": "file",
        "modified": get_modified(file_path).isoformat(),
        "length": os.path.getsize(file_path),
        "blocks": block_hashes,
        "hash": get_file_hash(block_hashes),
        "version": None
    }


def calculate_actions(local_dir_state_contents, server_dir_contents):
    actions = []
    return actions



def get_block_hashes(file_path):
    """ Get the hashes for the blocks in a local file """
    file_length = os.path.getsize(file_path)
    block_count = math.ceil(file_length/BLOCK_LENGTH)
    return [get_hash(read_block(file_path, block_number)) for block_number in range(0, block_count)]


def get_file_hash(block_hashes):
    if len(block_hashes) == 1:
        return block_hashes[0]
    else:
        all_hashes = "\n".join(block_hashes) + "\n"
        return get_hash(all_hashes.encode("utf-8"))


def read_block(file_path, block_number):
    offset = block_number * BLOCK_LENGTH
    file_length = os.path.getsize(file_path)
    if (offset + BLOCK_LENGTH) < file_length:
        read_length = BLOCK_LENGTH
    else:
        read_length = file_length - offset
    with open(file_path, "rb") as input_file:
        input_file.seek(offset)
        data = input_file.read(read_length)
    return data


def get_hash(data):
    """ Get the hash for some data """
    message = hashlib.sha256()
    message.update(data)
    return message.hexdigest()


def update_dir_state_entry(file_path, dir_state_entry):
    return None

def get_modified(file_path):
    return datetime.datetime.fromtimestamp(int(os.path.getmtime(file_path)))

def get_now_iso():
    return datetime.datetime.now().isoformat()

def load_dir_state_file(dir_path, url):
    path = os.path.join(os.path.abspath(dir_path), SYNC_FILE_NAME)
    if not os.path.exists(path):
        return {}
    with open(path) as input_file:
        jsn = json.load(input_file)
        if not url in jsn:
            return {}
        else:
            return jsn[url]

def get_json(url, params=None):
    get_token(url)
    global USER_TOKEN
    headers = {"Authorization": "bearer " + USER_TOKEN}
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

def get_server_directory_state(url):
    params = {"return_dict": True}
    server_dir_list = get_json(url, params=params)
    return server_dir_list["children"]


if __name__ == '__main__':
    main()


