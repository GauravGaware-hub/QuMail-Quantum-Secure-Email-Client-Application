import requests

url = "http://127.0.0.1:5000/api/keys"
headers = {
    "Authorization": "Bearer demo-token",
    "Content-Type": "application/json"
}
data = {
    "user": "your_email@gmail.com",
    "key_length": 32
}

response = requests.post(url, json=data, headers=headers)
print("Status code:", response.status_code)
print("Response JSON:", response.json())