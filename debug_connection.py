"""
Debug script to validate DVWA connection and XSS testing
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def test_connection():
    """Test basic connection to DVWA."""
    print("=" * 70)
    print("DVWA CONNECTION & XSS DEBUG TEST")
    print("=" * 70)
    
    # Test 1: Can we reach DVWA at all?
    print("\n[TEST 1] Testing basic connection to DVWA...")
    try:
        response = requests.get("http://localhost/dvwa/", timeout=10)
        print(f"✅ Connection successful!")
        print(f"   Status Code: {response.status_code}")
        print(f"   Response Length: {len(response.text)} chars")
        
        # Check if we're being redirected to login
        if "login" in response.url.lower() or "login.php" in response.text.lower():
            print("⚠️  We're being redirected to login page!")
            print(f"   Current URL: {response.url}")
            return False
        
    except Exception as e:
        print(f"❌ Connection FAILED: {e}")
        return False
    
    # Test 2: Try XSS page without authentication
    print("\n[TEST 2] Testing XSS page without authentication...")
    url = "http://localhost/dvwa/vulnerabilities/xss_r/"
    
    try:
        response = requests.get(url, timeout=10)
        print(f"   Status Code: {response.status_code}")
        print(f"   Final URL: {response.url}")
        
        # Check for login redirect
        if "login" in response.url.lower():
            print("❌ REDIRECTED TO LOGIN PAGE")
            print("   You need to authenticate first!")
            return False
        
        # Check if XSS form is present
        if 'name=' in response.text or 'input' in response.text.lower():
            print("✅ XSS page accessible (form found)")
        else:
            print("⚠️  Page accessible but no form found")
            
    except Exception as e:
        print(f"❌ XSS page access FAILED: {e}")
        return False
    
    # Test 3: Try with a simple test payload
    print("\n[TEST 3] Testing simple payload injection...")
    test_payload = "TEST123"
    test_url = f"{url}?name={test_payload}"
    
    try:
        response = requests.get(test_url, timeout=10)
        print(f"   Request URL: {test_url}")
        print(f"   Status Code: {response.status_code}")
        
        if test_payload in response.text:
            print(f"✅ Payload REFLECTED in response!")
            print(f"   Found '{test_payload}' in HTML")
        else:
            print(f"❌ Payload NOT reflected")
            print(f"   '{test_payload}' not found in response")
            
        # Show snippet of response
        print(f"\n   Response snippet (first 500 chars):")
        print(f"   {response.text[:500]}")
        
    except Exception as e:
        print(f"❌ Payload test FAILED: {e}")
        return False
    
    # Test 4: Try actual XSS payload
    print("\n[TEST 4] Testing XSS payload...")
    xss_payload = "<script>alert(1)</script>"
    xss_url = f"{url}?name={xss_payload}"
    
    try:
        response = requests.get(xss_url, timeout=10)
        print(f"   XSS Payload: {xss_payload}")
        print(f"   Status Code: {response.status_code}")
        
        # Check what we got back
        if "<script>alert(1)</script>" in response.text:
            print("✅ XSS payload PASSED THROUGH unchanged!")
            print("   Vulnerability likely present (Low security)")
        elif "script" in response.text.lower() and "alert" in response.text.lower():
            print("⚠️  XSS payload partially present")
            print("   Might be filtered/encoded")
        elif "&lt;script&gt;" in response.text:
            print("⚠️  XSS payload HTML-ENCODED")
            print("   DVWA is filtering (Medium/High security)")
        else:
            print("❌ XSS payload completely REMOVED")
            print("   Heavy filtering in place")
        
        # Show where our payload ended up
        if "name" in response.text:
            import re
            matches = re.findall(r'name["\s]*[:=]["\s]*([^"<>]{0,100})', response.text, re.IGNORECASE)
            if matches:
                print(f"\n   Payload in response: {matches[0][:100]}")
        
    except Exception as e:
        print(f"❌ XSS test FAILED: {e}")
        return False
    
    # Test 5: Check if we need authentication
    print("\n[TEST 5] Checking authentication requirements...")
    
    if "login" in response.text.lower() or "username" in response.text.lower():
        print("❌ Authentication REQUIRED")
        print("\n   SOLUTION: You need to login to DVWA first!")
        print("   1. Open browser: http://localhost/dvwa/login.php")
        print("   2. Login (default: admin/password)")
        print("   3. Then use session cookies in script")
        return False
    else:
        print("✅ No authentication required (or already bypassed)")
    
    return True


def test_with_session():
    """Test with manual session (if you provide cookies)."""
    print("\n" + "=" * 70)
    print("TESTING WITH SESSION/COOKIES")
    print("=" * 70)
    
    print("\nTo test with authentication, you need to:")
    print("1. Login to DVWA in browser")
    print("2. Get PHPSESSID cookie from browser")
    print("3. Add it here")
    print("\nExample:")
    print("  cookies = {'PHPSESSID': 'your_session_id_here', 'security': 'low'}")
    
    # Try with common default session
    print("\n[TEST 6] Attempting with default cookies...")
    
    session = requests.Session()
    
    # Common DVWA cookies (you may need to update these)
    cookies = {
        'security': 'low',  # Force low security
    }
    
    url = "http://localhost/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>"
    
    try:
        response = session.get(url, cookies=cookies, timeout=10)
        print(f"   Status Code: {response.status_code}")
        
        if "<script>alert(1)</script>" in response.text:
            print("✅ XSS VULNERABLE with session!")
        else:
            print("⚠️  Still filtered even with low security cookie")
            
    except Exception as e:
        print(f"❌ Session test failed: {e}")


def test_dvwa_login():
    """Try to login to DVWA automatically."""
    print("\n" + "=" * 70)
    print("ATTEMPTING AUTOMATIC LOGIN")
    print("=" * 70)
    
    session = requests.Session()
    login_url = "http://localhost/dvwa/login.php"
    
    print("\n[LOGIN TEST] Trying to authenticate...")
    print(f"   URL: {login_url}")
    
    try:
        # First, get the login page to get any tokens
        response = session.get(login_url, timeout=10)
        print(f"   Login page status: {response.status_code}")
        
        # Try default credentials
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login'
        }
        
        print(f"   Attempting login with username: {login_data['username']}")
        response = session.post(login_url, data=login_data, timeout=10)
        
        # Check if login successful
        if response.status_code == 200:
            if "logout" in response.text.lower() or "welcome" in response.text.lower():
                print("✅ LOGIN SUCCESSFUL!")
                
                # Now try XSS with authenticated session
                print("\n[AUTHENTICATED XSS TEST]")
                xss_url = "http://localhost/dvwa/vulnerabilities/xss_r/?name=<img src=x onerror=alert(1)>"
                response = session.get(xss_url, timeout=10)
                
                print(f"   Status: {response.status_code}")
                if "onerror" in response.text and "alert" in response.text:
                    print("✅ XSS PAYLOAD REFLECTED (Authenticated)!")
                    print("   DVWA is vulnerable!")
                    
                    # Show the security level
                    sec_url = "http://localhost/dvwa/security.php"
                    sec_response = session.get(sec_url, timeout=10)
                    if "low" in sec_response.text.lower():
                        print("   Security Level: LOW")
                    elif "medium" in sec_response.text.lower():
                        print("   Security Level: MEDIUM")
                    elif "high" in sec_response.text.lower():
                        print("   Security Level: HIGH")
                    
                    return session
                else:
                    print("⚠️  Authenticated but XSS still filtered")
            else:
                print("❌ Login failed - check credentials")
                print(f"   Response contains: {response.text[:200]}")
        else:
            print(f"❌ Login request failed with status {response.status_code}")
            
    except Exception as e:
        print(f"❌ Login attempt FAILED: {e}")
        return None


def main():
    """Run all debug tests."""
    print("\n🔍 STARTING DVWA CONNECTION DIAGNOSTICS\n")
    
    # Run basic tests
    basic_ok = test_connection()
    
    # Try session-based test
    test_with_session()
    
    # Try automatic login
    session = test_dvwa_login()
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY & RECOMMENDATIONS")
    print("=" * 70)
    
    if not basic_ok:
        print("\n❌ BASIC CONNECTION FAILED")
        print("\nRECOMMENDATIONS:")
        print("1. Check if DVWA is running: http://localhost/dvwa/")
        print("2. Make sure Docker container is up (if using Docker)")
        print("3. Login to DVWA manually first")
        print("4. Set security level to 'low'")
    else:
        print("\n✅ CONNECTION WORKS")
        print("\nNEXT STEPS:")
        print("1. If you see authentication errors, use the session approach")
        print("2. Make sure DVWA security is set to LOW")
        print("3. Run main_gaxss.py with authenticated session")


if __name__ == '__main__':
    main()
