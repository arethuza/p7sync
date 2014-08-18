import unittest
import p7sync
import requests
import os
import shutil
import math
import json
import shutil

HOME_FOLDER_URL = "http://localhost:8080/home"
SERVER_FOLDER_URL = "http://localhost:8080/home/test"
USER_NAME = "system"
USER_PASSWORD = "password"
LOCAL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dir")
LOCAL_FOLDER2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dir2")

class ClientTests(unittest.TestCase):

    def setUp(self):
        delete(SERVER_FOLDER_URL)
        create(HOME_FOLDER_URL, "test", "folder")
        if os.path.exists(LOCAL_FOLDER):
            shutil.rmtree(LOCAL_FOLDER)
        os.makedirs(LOCAL_FOLDER)
        if os.path.exists(LOCAL_FOLDER2):
            shutil.rmtree(LOCAL_FOLDER2)
        os.makedirs(LOCAL_FOLDER2)

    def tearDown(self):
        delete(SERVER_FOLDER_URL)
        shutil.rmtree(LOCAL_FOLDER)

    def test_sync_create_delete_single_file(self):
        client_authenticate()
        # Create a file locally
        create_file("foo")
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(1, len(server_contents))
        self.assertTrue("foo" in server_contents)
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(b'\x00' * 100, data)
        # Delete file locally
        delete_file("foo")
        # Sync again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check file is gone from server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(0, len(server_contents))
        self.assertTrue("foo" not in server_contents)

    def test_sync_create_delete_empty_file(self):
        client_authenticate()
        # Create a file locally
        create_file("foo", length=0)
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(1, len(server_contents))
        self.assertTrue("foo" in server_contents)
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(b'', data)
        # Delete file locally
        delete_file("foo")
        # Sync again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check file is gone from server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(0, len(server_contents))
        self.assertTrue("foo" not in server_contents)

    def test_sync_create_delete_multiple_files(self):
        client_authenticate()
        # Create a file locally
        create_file("foo")
        create_file("bar", length=0)
        create_file("raz", length=2000)
        # Sync again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(3, len(server_contents))
        self.assertTrue("foo" in server_contents)
        self.assertTrue("bar" in server_contents)
        self.assertTrue("raz" in server_contents)
        # Delete foo locally
        delete_file("foo")
        # Sync again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check file is gone from server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(2, len(server_contents))
        self.assertTrue("foo" not in server_contents)
        self.assertTrue("bar" in server_contents)
        self.assertTrue("raz" in server_contents)
        # Delete remaining files locally
        delete_file("bar")
        delete_file("raz")
        # Sync again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check file is gone from server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(0, len(server_contents))
        self.assertTrue("foo" not in server_contents)
        self.assertTrue("bar" not in server_contents)
        self.assertTrue("raz" not in server_contents)

    def test_sync_create_delete_single_file_large(self):
        client_authenticate()
        # Create a file locally
        create_file("foo", length=int(math.pow(2, 23)))
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(1, len(server_contents))
        self.assertTrue("foo" in server_contents)
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(math.pow(2, 23), len(data))
        # Delete file locally
        delete_file("foo")
        # Sync again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check file is gone from server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(0, len(server_contents))
        self.assertTrue("foo" not in server_contents)

    def test_update_file(self):
        client_authenticate()
        # Create a file locally
        create_file("foo")
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(1, sync_entry["file_version"])
        self.assertEquals(100, sync_entry["file_length"])
        self.assertIsNone(sync_entry["block_hashes"])
        self.assertEquals("0a3fb59710f6f76545c451d0b3198a45a8ab2bebd7ee298ddc80a0bd03597aa8", sync_entry["file_hash"])
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(1, len(server_contents))
        self.assertTrue("foo" in server_contents)
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(b'\x00' * 100, data)
        # Get the metadata for the file
        response = get_json(SERVER_FOLDER_URL + "/foo?view=meta")
        props = response["props"]
        self.assertEquals(1, props["file_version"])
        self.assertEquals(100, props["file_length"])
        self.assertIsNone(sync_entry["block_hashes"])
        self.assertEquals("0a3fb59710f6f76545c451d0b3198a45a8ab2bebd7ee298ddc80a0bd03597aa8", props["file_hash"])
        # Update the file
        update_file("foo", 2, offset=100, contents=b'1')
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(2, sync_entry["file_version"])
        self.assertEquals(102, sync_entry["file_length"])
        self.assertIsNone(sync_entry["block_hashes"])
        self.assertEquals("f993ee48e1fe66e3ddda9a9426b7d6680fb4d8c0ca604af5b35ff3107f6b2c99", sync_entry["file_hash"])
        # Get the metadata for the file
        response = get_json(SERVER_FOLDER_URL + "/foo?view=meta")
        props = response["props"]
        self.assertEquals(2, props["file_version"])
        self.assertEquals(102, props["file_length"])
        self.assertIsNone(sync_entry["block_hashes"])
        self.assertEquals("f993ee48e1fe66e3ddda9a9426b7d6680fb4d8c0ca604af5b35ff3107f6b2c99", props["file_hash"])
        # Delete file locally
        delete_file("foo")
        # Sync again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        self.assertEquals(0, len(sync_data_for_url))
        # Check file is gone from server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(0, len(server_contents))
        self.assertTrue("foo" not in server_contents)

    def test_update_file_large(self):
        client_authenticate()
        # Create a file locally
        create_file("foo", length=int(p7sync.BLOCK_LENGTH * 3.1))
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(0, sync_entry["file_version"])
        self.assertEquals(13002342, sync_entry["file_length"])
        self.assertIsNotNone(sync_entry["block_hashes"])
        self.assertEquals("50b79ed41ba49a9d1c5f201faee937596558d6f3045e9ae79e8846ae91af4f32", sync_entry["file_hash"])
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(1, len(server_contents))
        self.assertTrue("foo" in server_contents)
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(b'0' * 13002342, data)
        # Modify a small part of the file
        update_file("foo", offset=100, length=2, contents=b'1')
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(1, sync_entry["file_version"])
        self.assertEquals(13002342, sync_entry["file_length"])
        self.assertIsNotNone(sync_entry["block_hashes"])
        self.assertEquals("31acf5958904d5338e49b69add031476ba2a55cb6d5acbeb5224770a06674117", sync_entry["file_hash"])
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(13002342, len(data))
        self.assertEquals(48, data[99])
        self.assertEquals(49, data[100])
        self.assertEquals(49, data[101])
        self.assertEquals(48, data[102])
        # Modify the file so it is exactly 2 blocks long
        create_file("foo", length=p7sync.BLOCK_LENGTH * 2, contents=b'2')
        # Sync yet again
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(2, sync_entry["file_version"])
        self.assertEquals(2 * p7sync.BLOCK_LENGTH, sync_entry["file_length"])
        self.assertIsNotNone(sync_entry["block_hashes"])
        self.assertEquals("967d6d6e037db5e3096738017ace6508ef3ef2b288205191a76c1f737fc41b79", sync_entry["file_hash"])
        # Get the versions of the file
        versions = get_json(SERVER_FOLDER_URL + "/foo?versions=true")
        self.assertEquals(3, len(versions))
        self.assertIsNone(versions[0]["previous_version"])
        self.assertEquals(0, versions[1]["previous_version"])
        self.assertEquals(1, versions[2]["previous_version"])

    def test_file_in_folder(self):
        client_authenticate()
        # Create a file locally
        create_file("foo", folder="f1")
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        self.assertEquals(1, len(sync_data_for_url))
        sync_entry = sync_data_for_url["f1"]
        self.assertEquals(1, len(sync_entry))
        self.assertEquals("dir", sync_entry["type"])
        # Check on server
        response = get_json(SERVER_FOLDER_URL + "/f1")
        children = response["children"]
        self.assertEquals(1, len(children))
        child_entry = children[0]
        self.assertEquals("foo", child_entry["name"])
        props = child_entry["props"]
        self.assertEquals(1, props["file_version"])
        self.assertEquals(100, props["file_length"])
        self.assertEquals("0a3fb59710f6f76545c451d0b3198a45a8ab2bebd7ee298ddc80a0bd03597aa8", props["file_hash"])
        # Delete the file from the folder
        delete_file("foo", folder="f1")
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check on server
        response = get_json(SERVER_FOLDER_URL + "/f1")
        children = response["children"]
        self.assertEquals(0, len(children))
        # Delete the folder
        delete_dir("f1")
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Check on server
        self.assertIsNone(get_json(SERVER_FOLDER_URL + "/f1"))
        response = get_json(SERVER_FOLDER_URL)
        children = response["children"]
        self.assertEquals(0, len(children))

    def test_download_file(self):
        client_authenticate()
        # Create a file locally & sync
        create_file("foo")
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Download to folder 2
        p7sync.sync(LOCAL_FOLDER2, SERVER_FOLDER_URL)
        # Check what we have locally
        sync_file_contents = load_local_sync_file(folder=LOCAL_FOLDER2)
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(1, sync_entry["file_version"])
        self.assertEquals(100, sync_entry["file_length"])
        self.assertIsNone(sync_entry["block_hashes"])
        self.assertEquals("0a3fb59710f6f76545c451d0b3198a45a8ab2bebd7ee298ddc80a0bd03597aa8", sync_entry["file_hash"])

    def test_download_large_file(self):
        client_authenticate()
        # Create a file locally & sync
        create_file("foo", length=p7sync.BLOCK_LENGTH * 3)
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Download to folder 2
        p7sync.sync(LOCAL_FOLDER2, SERVER_FOLDER_URL)
        # Check what we have locally
        sync_file_contents = load_local_sync_file(folder=LOCAL_FOLDER2)
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(0, sync_entry["file_version"])
        self.assertEquals(p7sync.BLOCK_LENGTH * 3, sync_entry["file_length"])
        self.assertEquals(3, len(sync_entry["block_hashes"]))
        self.assertEquals("87bf23bc8ecbabac5b4474e090672b93acb47cb3ceea8ea19fc035482de1dbce", sync_entry["file_hash"])
        # Modify a small part of the file
        update_file("foo", offset=100, length=2, contents=b'1')
        # Sync change
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Download to folder 2
        local_to_server_actions, server_to_local_actions = p7sync.sync(LOCAL_FOLDER2, SERVER_FOLDER_URL)
        self.assertEquals([], local_to_server_actions)
        # Make sure we are only downloading one block
        self.assertEquals(3, len(server_to_local_actions))
        self.assertEquals("backup-file", server_to_local_actions[0][0])
        self.assertEquals("get-block", server_to_local_actions[1][0])
        self.assertEquals("check-file", server_to_local_actions[2][0])
        # Check what we have locally
        sync_file_contents = load_local_sync_file(folder=LOCAL_FOLDER2)
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(1, sync_entry["file_version"])
        self.assertEquals(p7sync.BLOCK_LENGTH * 3, sync_entry["file_length"])
        self.assertEquals(3, len(sync_entry["block_hashes"]))
        self.assertEquals("0d4749962eb0411ced9bd2d1406f58de997bdfcad687ac86ab9c5f85284d4f6d", sync_entry["file_hash"])
        # Create a shorter file
        create_file("foo", length=int(p7sync.BLOCK_LENGTH * 1.5))
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Download to folder 2
        p7sync.sync(LOCAL_FOLDER2, SERVER_FOLDER_URL)
        # Check what we have locally
        sync_file_contents = load_local_sync_file(folder=LOCAL_FOLDER2)
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        sync_entry = sync_data_for_url["foo"]
        self.assertEquals(2, sync_entry["file_version"])
        self.assertEquals(int(p7sync.BLOCK_LENGTH * 1.5), sync_entry["file_length"])
        self.assertEquals(2, len(sync_entry["block_hashes"]))
        self.assertEquals("faef5fa98ef7915cf2d865b112ed0fd7c5f8ca3336e52716ee661fab5f833807", sync_entry["file_hash"])

    def test_download_file_in_folder(self):
        client_authenticate()
        # Create a file locally
        create_file("foo", folder="f1")
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Download to folder 2
        p7sync.sync(LOCAL_FOLDER2, SERVER_FOLDER_URL)
        # Check local sync file contents
        sync_file_contents = load_local_sync_file()
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        self.assertEquals(1, len(sync_data_for_url))
        sync_entry = sync_data_for_url["f1"]
        self.assertEquals(1, len(sync_entry))
        self.assertEquals("dir", sync_entry["type"])
        # Check on server
        response = get_json(SERVER_FOLDER_URL + "/f1")
        children = response["children"]
        self.assertEquals(1, len(children))
        child_entry = children[0]
        self.assertEquals("foo", child_entry["name"])
        props = child_entry["props"]
        self.assertEquals(1, props["file_version"])
        self.assertEquals(100, props["file_length"])
        self.assertEquals("0a3fb59710f6f76545c451d0b3198a45a8ab2bebd7ee298ddc80a0bd03597aa8", props["file_hash"])
        # Check sync file contents for top level folder
        sync_file_contents = load_local_sync_file(LOCAL_FOLDER2)
        self.assertIsNotNone(sync_data_for_url)
        sync_entry = sync_data_for_url["f1"]
        self.assertIsNotNone(sync_entry)
        self.assertEquals("dir", sync_entry["type"])
        # Check file in folder
        sync_file_contents = load_local_sync_file(folder=os.path.join(LOCAL_FOLDER2, "f1"))
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL + "/f1"]
        self.assertIsNotNone(sync_data_for_url)
        sync_entry = sync_data_for_url["foo"]
        self.assertIsNotNone(sync_entry)
        self.assertEquals(1, sync_entry["file_version"])
        self.assertEquals(100, sync_entry["file_length"])
        self.assertEquals("0a3fb59710f6f76545c451d0b3198a45a8ab2bebd7ee298ddc80a0bd03597aa8", sync_entry["file_hash"])
        # Delete
        delete_file("foo", folder="f1")
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Sync to folder 2
        p7sync.sync(LOCAL_FOLDER2, SERVER_FOLDER_URL)
        # Check file isn't there anymore
        self.assertFalse(os.path.exists(os.path.join(LOCAL_FOLDER2, "f1", "foo")))
        # But the folder is
        self.assertTrue(os.path.exists(os.path.join(LOCAL_FOLDER2, "f1")))
        # Check sync file contents for top level folder
        sync_file_contents = load_local_sync_file(LOCAL_FOLDER2)
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        self.assertIsNotNone(sync_data_for_url)
        sync_entry = sync_data_for_url["f1"]
        self.assertIsNotNone(sync_entry)
        self.assertEquals("dir", sync_entry["type"])
        # Check sync file contents for sub folder
        sync_file_contents = load_local_sync_file(folder=os.path.join(LOCAL_FOLDER2, "f1"))
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL + "/f1"]
        self.assertIsNotNone(sync_data_for_url)
        self.assertEquals(0, len(sync_data_for_url))
        # Delete the sub folder
        shutil.rmtree(os.path.join(LOCAL_FOLDER, "f1"))
        # Sync
        p7sync.sync(LOCAL_FOLDER, SERVER_FOLDER_URL)
        # Sync to folder 2
        p7sync.sync(LOCAL_FOLDER2, SERVER_FOLDER_URL)
        # Folder isn't there anymore
        self.assertFalse(os.path.exists(os.path.join(LOCAL_FOLDER2, "f1")))
        # Check sync file contents for top level folder
        sync_file_contents = load_local_sync_file(LOCAL_FOLDER2)
        sync_data_for_url = sync_file_contents[SERVER_FOLDER_URL]
        self.assertIsNotNone(sync_data_for_url)
        self.assertFalse("f1" in sync_data_for_url)


def authenticate():
    data = { "name": USER_NAME, "password": USER_PASSWORD}
    response = requests.post(HOME_FOLDER_URL, data=data)
    global auth_token
    return response.json["token"]

auth_token = authenticate()


def client_authenticate():
    p7sync.USER_NAME = USER_NAME
    p7sync.USER_PASSWORD = USER_PASSWORD
    p7sync.get_token(HOME_FOLDER_URL)



def delete(url):
    headers = {
        "Authorization": "Bearer " + auth_token
    }
    response = requests.delete(url, headers=headers)
    pass

def create(parent_url, name, type):
    headers = {
        "Authorization": "Bearer " + auth_token
    }
    data = {
        "name": name,
        "type": type
    }
    requests.post(parent_url, headers=headers, data=data)

def list_server(url):
    headers = {
        "Authorization": "Bearer " + auth_token
    }
    params = {
        "return_dict": True
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json["children"]

def get_json(url):
    headers = {
        "Authorization": "Bearer " + auth_token
    }
    response = requests.get(url, headers=headers)
    return response.json


def get_file_data(url):
    headers = {
        "Authorization": "Bearer " + auth_token
    }
    return requests.get(url, headers=headers).content

def create_file(name, length=100, contents=b'\x00', folder=None):
    data = contents * length
    if folder is None:
        path = os.path.join(LOCAL_FOLDER, name)
    else:
        folder_path = os.path.join(LOCAL_FOLDER, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        path = os.path.join(folder_path, name)
    with open(path, "wb") as output_file:
        output_file.write(data)

def update_file(name, length, offset=0, contents=b'\x01'):
    data = contents * length
    path = os.path.join(LOCAL_FOLDER, name)
    with open(path, "r+b") as output_file:
        output_file.seek(offset)
        output_file.write(data)

def delete_file(name, folder=None):
    if folder is None:
        path = os.path.join(LOCAL_FOLDER, name)
    else:
        folder_path = os.path.join(LOCAL_FOLDER, folder)
        path = os.path.join(folder_path, name)
    os.remove(path)

def delete_dir(name):
    path = os.path.join(LOCAL_FOLDER, name)
    shutil.rmtree(path)


def load_local_sync_file(folder=LOCAL_FOLDER):
    path = os.path.join(folder, p7sync.SYNC_FILE_NAME)
    with open(path, "r") as input_file:
        data = input_file.read()
        return json.loads(data)


if __name__ == '__main__':
    unittest.main()

