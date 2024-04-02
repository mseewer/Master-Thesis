import requests
import json
server_ip = "192.168.111.1"


# GET request to the server
def get_request(endpoint: str):
    response = requests.get(f"https://{server_ip}/api/v1{endpoint}", verify=False)
    print(response.text)
    print(response.status_code)

def put_request(endpoint, data):
    # type is application/json
    response = requests.put(f"https://{server_ip}/api/v1{endpoint}", verify=False, headers={"Content-Type": "application/json"}, json=data)
    print(response.text)
    print(response.status_code)

def post_request(endpoint, data):
    # type is application/json
    response = requests.post(f"https://{server_ip}/api/v1{endpoint}", verify=False, headers={"Content-Type": "application/json"}, json=data)
    print(response.text)
    print(response.status_code)

if __name__ == "__main__":
    get_request("/config")

    with open ("old_config.json", "r") as f:
        old_config = json.load(f)
    config = old_config["config"]
    # metadata = old_config["metadata"]
    data = {
        "config": config,
    }

    put_request("/config", data)
    input("Press Enter to continue...")
    post_request("/config/validate", data)
