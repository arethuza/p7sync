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
    local_to_server_actions = calculate_local_to_server_actions(dir_path, url, local_changes, current_sync_state)
    perform_local_to_server_actions(local_to_server_actions, current_sync_state)
    # pull server changes locally
    server_state = get_server_directory_state(url)

    server_to_local_actions = calculate_server_to_local_actions(dir_path, url, current_sync_state, server_state)
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
                local_changes.append(("created-file", name, None, changed_blocks))
            else:
                # A file we have seen before
                previous_sync_state_entry = previous_sync_state[name]
                previous_length = previous_sync_state_entry["file_length"]
                current_length = os.path.getsize(path)
                previous_modified = dateutil.parser.parse(previous_sync_state_entry["modified"])
                current_modified = get_modified(path)
                if (current_length != previous_length) or (current_modified > previous_modified):
                    # Only calculate new entry if file may have changed
                    updated_entry = create_sync_state_entry(path)
                    sync_state_entry = current_sync_state[name]
                    lengths_differ = updated_entry["file_length"] != sync_state_entry["file_length"]
                    hashes_differ = updated_entry["file_hash"] != sync_state_entry["file_hash"]
                    if lengths_differ or hashes_differ:
                        current_sync_state[name] = updated_entry
                        previous_blocks = previous_sync_state_entry["block_hashes"]
                        updated_blocks = updated_entry["block_hashes"]
                        changed_blocks = get_changed_blocks(previous_blocks, updated_blocks)
                        version = previous_sync_state_entry["file_version"]
                        local_changes.append(("updated-file", name, version, changed_blocks))
        elif os.path.isdir(path):
            if not name in current_sync_state:
                current_sync_state[name] = {"type": "dir"}
                local_changes.append(("created-dir", name))
            else:
                local_changes.append(("dir", name))
    return current_sync_state, local_changes


def create_sync_state_entry(file_path):
    block_hashes = get_block_hashes(file_path)
    result = {
        "type": "file",
        "modified": get_modified(file_path).isoformat(),
        "file_length": os.path.getsize(file_path),
        "file_hash": get_file_hash(block_hashes),
        "file_version": None,
        "block_hashes": block_hashes if len(block_hashes) > 1 else None
    }
    return result


def get_changed_blocks(blocks1, blocks2):
    if blocks2 is None:
        return None
    if blocks1 is None:
        return list(enumerate(blocks2))
    return [(block_number, block_hash2) for block_number, (block_hash1, block_hash2)
            in enumerate(itertools.zip_longest(blocks1, blocks2))
            if block_hash1 != block_hash2 and block_hash2 is not None]


def calculate_local_to_server_actions(dir_path, url, local_changes, local_sync_state):
    actions = []
    for change in local_changes:
        change_type = change[0]
        name = change[1]
        local_sync_state_entry = local_sync_state[name] if name in local_sync_state else None
        path = os.path.join(dir_path, name)
        resource_url = url + "/" + name
        if change_type == "created-file" or change_type == "updated-file":
            length = local_sync_state_entry["file_length"]
            version = change[2]
            if length <= BLOCK_LENGTH:
                actions.append(("put-file", path, name, resource_url))
            else:
                if version is None:
                    actions.append(("post-file", url, name))
                else:
                    actions.append(("post-file-version", resource_url, name, version))
                changed_blocks = change[3]
                last_block_number = math.ceil(length/BLOCK_LENGTH) - 1
                last_block_changed = last_block_number in (block_number for (block_number, _) in changed_blocks)
                for index, (block_number, block_hash) in enumerate(changed_blocks):
                    actions.append(("put-block", path, name, resource_url, block_number, block_hash,
                                    (last_block_changed and index == last_block_number)))
                if not last_block_changed:
                    actions.append(("put-block", path, name, resource_url, last_block_number, None, True))
        elif change_type == "deleted":
            actions.append(("delete-server", resource_url, None))
        elif change_type == "created-dir":
            actions.append(("post-folder-server", url, name))
            actions.append(("sync", path, resource_url))
        elif change_type == "dir":
            actions.append(("sync", path, resource_url))
    return actions


def perform_local_to_server_actions(actions, current_sync_state):
    for action in actions:
        action_name = action[0]
        if action_name != "sync":
            file_name = action[2]
            sync_state_entry = current_sync_state[file_name] if file_name is not None else None
            if action_name == "put-file":
                perform_put_file(action, sync_state_entry)
            elif action_name == "delete-server":
                perform_delete_server(action)
            elif action_name == "post-file":
                perform_post_file(action, sync_state_entry)
            elif action_name == "post-file-version":
                perform_post_file_version(action, sync_state_entry)
            elif action_name == "put-block":
                perform_put_block(action, sync_state_entry)
            elif action_name == "post-folder-server":
                perform_post_folder_server(action, sync_state_entry)
        else:
            perform_sync(action)

def calculate_server_to_local_actions(dir_path, url, current_sync_state, server_state):
    actions = []
    # Check for anything to delete locally
    for name, _ in current_sync_state.items():
        if not name in server_state:
            # Delete item locally
            path = os.path.join(dir_path, name)
            actions.append(("delete-local", path))
    # Compare what is on server to what we have locally
    for name, server_entry in server_state.items():
        entry_type = server_entry["type"]
        resource_url = url + "/" + name
        path = os.path.join(dir_path, name)
        if entry_type == "file":
            props = server_entry["props"]
            server_version = props["file_version"]
            file_length = props["file_length"]
            download_file = False
            if name in current_sync_state:
                local_entry = current_sync_state[name]
                local_version = local_entry["file_version"]
                download_file = local_version < server_version
            else:
                download_file = True
            if download_file:
                if file_length <= BLOCK_LENGTH:
                    # Download file in 1 go
                    actions.append(("get-file", url, path, server_version))
                else:
                    # Calculate blocks to download
                    local_block_hashes = local_entry["block_hashes"]
                    server_blocks_response = get_json(url, {"list_blocks": True, "file_version": server_version})
                    server_block_hashes = [block_hash for _, _, _, block_hash, _ in server_blocks_response]
        elif entry_type == "folder":
            pass

def perform_put_file(action, sync_state_entry):
    _, file_path, name, url = action
    file_length = sync_state_entry["file_length"]
    file_hash = sync_state_entry["file_hash"]
    file_version = sync_state_entry["file_version"]
    data = read_block(file_path, 0)
    response = put_data(url, data)
    props = response["props"]
    server_version, server_length, server_hash = props["file_version"], props["file_length"], props["file_hash"]
    assert file_length == server_length
    assert file_hash == server_hash
    sync_state_entry["file_version"] = server_version


def perform_delete_server(action):
    _, url, name = action
    delete_resource(url)


def perform_post_file(action, sync_state_entry):
    _, url, name = action
    data = {
        "name": name,
        "type": "file"
    }
    response = post(url, data)
    props = response["props"]
    sync_state_entry["file_version"] = props["file_version"]

def perform_post_file_version(action, sync_state_entry):
    _, url, _, version = action
    data = {
        "previous_version": version
    }
    response = post(url, data)
    sync_state_entry["file_version"] = response["file_version"]


def ensure_list_length(lst, length):
    if lst is None:
        return [None] * length
    lst_length = len(lst)
    if lst_length == length:
        return lst
    elif lst_length < length:
        return lst.extend([None] * (length - lst_length))
    elif lst_length > length:
        return lst[:length]


def perform_put_block(action, sync_state_entry):
    _, path, _, url, block_number, block_hash, last_block = action
    version = sync_state_entry["file_version"]
    data = read_block(path, block_number)
    params = {
        "file_version": version,
        "block_number": block_number,
        "last_block": last_block
    }
    response = put_data(url, data, params=params)
    if last_block:
        props = response["props"]
        server_block_hash = props["block_hash"]
        server_file_hash = props["file_hash"]
        server_file_length = props["file_length"]
        assert server_file_hash == sync_state_entry["file_hash"]
        assert server_file_length == sync_state_entry["file_length"]
    else:
        server_block_hash = response["block_hash"]
    if block_hash is not None:
        assert server_block_hash == block_hash

def perform_post_folder_server(action, server_state_entry):
    _, url, name = action
    data = {
        "name": name,
        "type": "folder"
    }
    response = post(url, data)

def perform_sync(action):
    _, dir_path, url = action
    sync(dir_path, url)

def get_block_hashes(file_path):
    """ Get the hashes for the blocks in a local file """
    file_length = os.path.getsize(file_path)
    block_count = math.ceil(file_length/BLOCK_LENGTH)
    return [get_hash(read_block(file_path, block_number)) for block_number in range(0, block_count)]


def get_file_hash(block_hashes):
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
    headers = {"Authorization": "Bearer " + USER_TOKEN}
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
        "Authorization": "Bearer " + USER_TOKEN,
        "Content-Type": "application/octet-stream",
        "Content-Length" : str(len(data))
    }
    response = requests.put(url, data=data, headers=headers, params=params)
    return response.json

def post(url, data):
    get_token(url)
    global USER_TOKEN
    headers = {
        "Authorization": "Bearer " + USER_TOKEN
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        raise Exception()
    return response.json

def delete_resource(url):
    get_token(url)
    global USER_TOKEN
    headers = {
        "Authorization": "Bearer " + USER_TOKEN,
    }
    response = requests.delete(url, headers=headers)
    if response.status_code != 200:
        raise Exception()

if __name__ == '__main__':
    main()


