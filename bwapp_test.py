import requests
import sys

def test_bwapp_login():
    base_url = "http://localhost:8082"
    login_url = f"{base_url}/login.php"
    
    print(f"[*] Testing login to {login_url}")
    
    session = requests.Session()
    
    # 1. Payload including the critical security_level field
    payload = {
        "login": "bee",
        "password": "bug",
        "security_level": "0",  # 0 = Low
        "form": "submit"
    }
    
    try:
        # 2. Perform Login
        response = session.post(login_url, data=payload, allow_redirects=True)
        
        print(f"[*] Status Code: {response.status_code}")
        print(f"[*] Final URL: {response.url}")
        
        # 3. Analyze Result
        if "Invalid credentials" in response.text:
            print("[-] FAILED: Invalid credentials message detected.")
            return False
            
        if "Logout" in response.text:
            print("[+] SUCCESS: Found 'Logout' link in response.")
            print("[+] Authentication cookies captured:")
            for cookie in session.cookies:
                print(f"    {cookie.name}: {cookie.value}")
            return True
        elif "portal.php" in response.url:
             print("[+] SUCCESS: Redirected to portal.php.")
             return True
        else:
            print("[-] FAILED: Could not find 'Logout' or redirection to portal.")
            print("[-] Response snippet:")
            print(response.text[:500])
            return False
            
    except Exception as e:
        print(f"[-] ERROR: {e}")
        return False

if __name__ == "__main__":
    if test_bwapp_login():
        print("\n[!] Login Config is FIXED. You can now run main_gaxss.py")
    else:
        print("\n[!] Login still failing. Check if bWAPP is actually running at port 8082.")
