import unittest
import p7sync
import requests
import os
import shutil
import math
import json

HOME_FOLDER_URL = "http://localhost:8080/home"
SERVER_FOLDER_URL = "http://localhost:8080/home/test"
USER_NAME = "system"
USER_PASSWORD = "password"
LOCAL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dir")

class ClientTests(unittest.TestCase):

    def setUp(self):
        delete(SERVER_FOLDER_URL)
        create(HOME_FOLDER_URL, "test", "folder")
        if os.path.exists(LOCAL_FOLDER):
            shutil.rmtree(LOCAL_FOLDER)
        os.makedirs(LOCAL_FOLDER)

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
        self.assertEquals(b'0' * 100, data)
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
        self.assertEquals("a32b7936a50b7da5e436c582186a6f9b6d5919640afca1d1dd17be67d6e52057", sync_entry["file_hash"])
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(1, len(server_contents))
        self.assertTrue("foo" in server_contents)
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(b'0' * 100, data)
        # Get the metadata for the file
        response = get_json(SERVER_FOLDER_URL + "/foo?view=meta")
        props = response["props"]
        self.assertEquals(1, props["file_version"])
        self.assertEquals(100, props["file_length"])
        self.assertIsNone(sync_entry["block_hashes"])
        self.assertEquals("a32b7936a50b7da5e436c582186a6f9b6d5919640afca1d1dd17be67d6e52057", props["file_hash"])
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
        self.assertEquals("84b2f309f4b3493f40b9fbfe1de040b163539ad234f9360ea03e8676d5bb3c3e", sync_entry["file_hash"])
        # Get the metadata for the file
        response = get_json(SERVER_FOLDER_URL + "/foo?view=meta")
        props = response["props"]
        self.assertEquals(2, props["file_version"])
        self.assertEquals(102, props["file_length"])
        self.assertIsNone(sync_entry["block_hashes"])
        self.assertEquals("84b2f309f4b3493f40b9fbfe1de040b163539ad234f9360ea03e8676d5bb3c3e", props["file_hash"])
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
        self.assertEquals("5fb0ff69587cad8c5050a84b4a729046333aa6077069b36c67ecca51fc316878", sync_entry["file_hash"])
        # Check what we have on server
        server_contents = list_server(SERVER_FOLDER_URL)
        self.assertEquals(1, len(server_contents))
        self.assertTrue("foo" in server_contents)
        # Get the file contents
        data = get_file_data(SERVER_FOLDER_URL + "/foo")
        self.assertEquals(b'0' * 13002342, data)

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
        "Authorization": "bearer " + auth_token
    }
    response = requests.delete(url, headers=headers)
    pass

def create(parent_url, name, type):
    headers = {
        "Authorization": "bearer " + auth_token
    }
    data = {
        "name": name,
        "type": type
    }
    requests.post(parent_url, headers=headers, data=data)

def list_server(url):
    headers = {
        "Authorization": "bearer " + auth_token
    }
    params = {
        "return_dict": True
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json["children"]

def get_json(url):
    headers = {
        "Authorization": "bearer " + auth_token
    }
    response = requests.get(url, headers=headers)
    return response.json


def get_file_data(url):
    headers = {
        "Authorization": "bearer " + auth_token
    }
    return requests.get(url, headers=headers).content

def create_file(name, length=100, contents=b'0'):
    data = contents * length
    path = os.path.join(LOCAL_FOLDER, name)
    with open(path, "wb") as output_file:
        output_file.write(data)

def update_file(name, length, offset=0, contents=b'0'):
    data = contents * length
    path = os.path.join(LOCAL_FOLDER, name)
    with open(path, "r+b") as output_file:
        output_file.seek(offset)
        output_file.write(data)

def delete_file(name):
    path = os.path.join(LOCAL_FOLDER, name)
    os.remove(path)

def load_local_sync_file():
    path = os.path.join(LOCAL_FOLDER, p7sync.SYNC_FILE_NAME)
    with open(path, "r") as input_file:
        data = input_file.read()
        return json.loads(data)


if __name__ == '__main__':
    unittest.main()

