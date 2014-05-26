import argparse
import os
import requests
import json
import datetime
import math
import hashlib
import copy
import dateutil.parser
import itertools

BLOCK_LENGTH=int(math.pow(2, 22))

USER_NAME = None
USER_PASSWORD = None
USER_TOKEN = None

SYNC_FILE_NAME = ".sync.json"

def main():
    command, dir_path, url = parse_args()
    if command == "sync":
        sync(dir_path, url)
    elif command == "changes":
        list_changes(dir_path)
    elif command == "update_local":
        update_local(dir_path, url)

def parse_args():
    parser = argparse.ArgumentParser(description='Sync using RedSquirrel')
    parser.add_argument("command", help="command to perform: sync")
    parser.add_argument("dir", help="local directory")
    parser.add_argument("--url", help="url of p7 folder")
    parser.add_argument("--user", help="username:password")
    global USER_NAME, USER_PASSWORD
    args = parser.parse_args()
    if args.user:
        USER_NAME, USER_PASSWORD = args.user.split(":")
    return args.command, args.dir, args.url


def sync(dir_path, url):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    previous_sync_state = load_sync_state(dir_path, url)
    current_sync_state, local_changes = update_sync_state(dir_path, previous_sync_state)
    # push local changes to server
    server_sync_state = get_server_directory_state(url)
    local_to_server_actions = calculate_local_to_server_actions(dir_path, url, local_changes, current_sync_state,
                                                                server_sync_state)
    perform_local_to_server_actions(local_to_server_actions)
    # Perform actions - updating current dir state
    if len(local_changes) > 0:
        update_sync_state_file(dir_path, url, current_sync_state)


def list_changes(dir_path):
    sync_file_contents = load_sync_file(dir_path)
    for url in sync_file_contents.keys():
        print(url)
        previous_sync_state = load_sync_state(dir_path, url)
        _, local_changes = update_sync_state(dir_path, previous_sync_state)
        for change in local_changes:
            print("\t" + str(change))

def update_local(dir_path, url):
    sync_file_contents = load_sync_file(dir_path)
    for url in sync_file_contents.keys():
        print(url)
        previous_sync_state = load_sync_state(dir_path, url)
        current_sync_state, local_changes = update_sync_state(dir_path, previous_sync_state)
        if len(local_changes) > 0:
            update_sync_state_file(dir_path, url, current_sync_state)
            for change in local_changes:
                print("\t" + str(change))

def update_sync_state(dir_path, previous_sync_state):
    local_changes = []
    # Start off with a copy of the previous state
    current_sync_state = copy.copy(previous_sync_state)
    for name, sync_state_entry in previous_sync_state.items():
        path = os.path.join(dir_path, name)
        entry_type = sync_state_entry["type"]
        type_has_changed = ((os.path.isfile(path) and entry_type == "dir") or
                           (os.path.isdir(path) and entry_type == "file"))
        # Delete any entries that have been deleted or changes between file and dir
        if not os.path.exists(path) or type_has_changed:
            del current_sync_state[name]
            local_changes.append(("deleted", name))
    # Look at the contents of the dir
    for name in os.listdir(dir_path):
        if name == SYNC_FILE_NAME:
            continue
        path = os.path.join(dir_path, name)
        if os.path.isfile(path):
            if not name in previous_sync_state:
                # A file has been created
                entry = current_sync_state[name] = create_sync_state_entry(path)
                changed_blocks = get_changed_blocks(None, entry["block_hashes"])
                local_changes.append(("created-file", name, changed_blocks))
            else:
                # A file we have seen before
                previous_sync_state_entry = previous_sync_state[name]
                previous_length = previous_sync_state_entry["length"]
                current_length = os.path.getsize(path)
                previous_modified = dateutil.parser.parse(previous_sync_state_entry["modified"])
                current_modified = get_modified(path)
                if (current_length != previous_length) or (current_modified > previous_modified):
                    # Only calculate new entry if file may have changed
                    updated_entry = create_sync_state_entry(path)
                    sync_state_entry = current_sync_state[name]
                    lengths_differ = updated_entry["length"] != sync_state_entry["length"]
                    hashes_differ = updated_entry["hash"] != sync_state_entry["hash"]
                    if lengths_differ or hashes_differ:
                        current_sync_state[name] = updated_entry
                        previous_blocks = previous_sync_state_entry["block_hashes"]
                        updated_blocks = updated_entry["block_hashes"]
                        changed_blocks = get_changed_blocks(previous_blocks, updated_blocks)
                        version = previous_sync_state_entry["version"]
                        local_changes.append(("updated-file", name, changed_blocks))
        elif os.path.isdir(path):
            if not name in current_sync_state:
                current_sync_state[name] = {"type": "dir"}
                local_changes.append(("created-dir", name))
    return current_sync_state, local_changes


def create_sync_state_entry(file_path):
    block_hashes = get_block_hashes(file_path)
    result = {
        "type": "file",
        "modified": get_modified(file_path).isoformat(),
        "length": os.path.getsize(file_path),
        "hash": get_file_hash(block_hashes),
        "version": None,
        "block_hashes": block_hashes if len(block_hashes) > 1 else None
    }
    return result

def get_changed_blocks(blocks1, blocks2):
    if blocks2 is None:
        return None
    if blocks1 is None:
        return list(enumerate(blocks2))
    return [(block_number, block_hash2) for block_number, (block_hash1, block_hash2)
            in enumerate(itertools.zip_longest(blocks1, blocks2)) if block_hash1 != block_hash2]

def calculate_local_to_server_actions(dir_path, url, local_changes, local_sync_state, server_sync_state):
    actions = []
    for change in local_changes:
        change_type = change[0]
        name = change[1]
        local_sync_state_entry = local_sync_state[name] if name in local_sync_state else None
        path = os.path.join(dir_path, name)
        resource_url = url + "/" + name
        if change_type == "created-file" or change_type == "updated-file":
            length = local_sync_state_entry["length"]
            file_hash = local_sync_state_entry["hash"]
            version = local_sync_state_entry["version"]
            if length <= BLOCK_LENGTH:
                actions.append(("put-file", path, resource_url, version, length, file_hash))
            else:
                actions.append(("post-file", url if version is None else resource_url, name, version))
                changed_blocks = change[2]
                last_changed_index = len(changed_blocks) - 1
                for index, (block_number, block_hash) in enumerate(changed_blocks):
                    actions.append(("put-block", path, resource_url, version, block_number, block_hash,
                                    index == last_changed_index))
                pass
        elif change_type == "deleted":
            actions.append(("delete-server", resource_url))
    return actions

def perform_local_to_server_actions(actions):
    for action in actions:
        action_name = action[0]
        if action_name == "put-file":
            perform_put_file(action)
        elif action_name == "delete-server":
            perform_delete_server(action)
        elif action_name == "post-file":
            perform_post_file(action)
        elif action_name == "put-block":
            perform_put_block(action)

def perform_put_file(action):
    _, file_path, url, version, file_length, file_hash = action
    data = read_block(file_path, 0)
    response = put_data(url, data)
    props = response["props"]
    version, server_length, server_hash = props["file_version"], props["file_length"], props["file_hash"]
    assert file_length == server_length
    assert file_hash == server_hash

def perform_delete_server(action):
    _, url = action
    delete_resource(url)

def perform_post_file(action):
    _, url, name, version = action
    data = {
        "name": name,
        "type": "file"
    }
    response = post(url, data)

def perform_put_block(action):
    _, path, url, version, block_number, block_hash, last_block = action
    data = read_block(path, block_number)
    params = {
        "file_version": 0,
        "block_number": block_number,
        "last_block": last_block
    }
    put_data(url, data, params=params)

def get_block_hashes(file_path):
    """ Get the hashes for the blocks in a local file """
    file_length = os.path.getsize(file_path)
    block_count = math.ceil(file_length/BLOCK_LENGTH)
    return [get_hash(read_block(file_path, block_number)) for block_number in range(0, block_count)]


def get_file_hash(block_hashes):
    if len(block_hashes) == 1:
        return block_hashes[0]
    else:
        all_hashes = "".join(block_hashes)
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

def get_modified(file_path):
    return datetime.datetime.fromtimestamp(int(os.path.getmtime(file_path)))

def get_now_iso():
    return datetime.datetime.now().isoformat()

def load_sync_state(dir_path, url):
    sync_file_contents = load_sync_file(dir_path)
    if url in sync_file_contents:
        return sync_file_contents[url]
    else:
        return {}

def load_sync_file(dir_path):
    path = os.path.join(os.path.abspath(dir_path), SYNC_FILE_NAME)
    if not os.path.exists(path):
        return {}
    else:
        with open(path) as input_file:
            return json.load(input_file)


def update_sync_state_file(dir_path, url, sync_state):
    path = os.path.join(os.path.abspath(dir_path), SYNC_FILE_NAME)
    if os.path.exists(path):
        with open(path) as input_file:
            sync_file_contents = json.load(input_file)
    else:
        sync_file_contents = {}
    sync_file_contents[url] = sync_state
    with open(path, "w") as output_file:
        json.dump(sync_file_contents, output_file, indent=4)


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

def put_data(url, data, params=None):
    get_token(url)
    global USER_TOKEN
    headers = {
        "Authorization": "bearer " + USER_TOKEN,
        "Content-Type": "application/octet-stream",
        "Content-Length" : str(len(data))
    }
    response = requests.put(url, data=data, headers=headers, params=params)
    return response.json

def post(url, data):
    get_token(url)
    global USER_TOKEN
    headers = {
        "Authorization": "bearer " + USER_TOKEN
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        raise Exception()
    return response.json

def delete_resource(url):
    get_token(url)
    global USER_TOKEN
    headers = {
        "Authorization": "bearer " + USER_TOKEN,
    }
    response = requests.delete(url, headers=headers)
    if response.status_code != 200:
        raise Exception()

if __name__ == '__main__':
    main()


