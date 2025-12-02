import requests
from bs4 import BeautifulSoup

session = requests.Session()

def login_dvwa(security_level="medium"):
    login_url = "http://localhost/dvwa/login.php"

    login_page = session.get(login_url)
    soup = BeautifulSoup(login_page.text, "lxml")

    token = soup.find("input", {"name": "user_token"})["value"]

    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }

    session.post(login_url, data=payload)
    session.cookies.set("security", security_level, domain="localhost", path="/")

    print(f"[+] DVWA logged in with security={security_level}")

def send_payload(url, param, payload):
    page = session.get(url)
    soup = BeautifulSoup(page.text, "lxml")

    try:
        token = soup.find("input", {"name": "user_token"})["value"]
    except:
        token = ""

    params = {param: payload, "user_token": token}
    response = session.get(url, params=params)

    return response.text
