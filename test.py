import requests

# Define Tor SOCKS5 proxy (socks5h ensures DNS resolves through Tor)
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

try:
    # Pass the proxies dictionary directly into requests
    response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=10)
    response2 = requests.get("http://httpbin.org/ip")
    
    # Print the readable response
    print("Your Tor IP address:")
    print(response.json()["origin"])
    print("old:")
    print(response2.json())

except requests.exceptions.RequestException as e:
    print(f"Could not connect through Tor: {e}")