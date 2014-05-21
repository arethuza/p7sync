import unittest
import p7sync
import requests
import os
import shutil
import math

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


if __name__ == '__main__':
    unittest.main()
