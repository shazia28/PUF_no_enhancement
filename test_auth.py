#!/usr/bin/env python3
"""Quick authentication test."""

from client import AuthenticationClient
import time

def test():
    print("Starting authentication test...")
    
    device_id = "device_test_auth"
    client = AuthenticationClient(device_id, 'localhost', 8888)
    
    try:
        # Connect
        if not client.connect():
            print("Failed to connect")
            return
        
        # Enroll
        print("\n1. Enrolling...")
        if not client.enroll():
            print("Enrollment failed")
            return
        
        time.sleep(1)
        
        # Authenticate
        print("\n2. Authenticating...")
        if client.authenticate():
            print("✓ Authentication successful!")
        else:
            print("✗ Authentication failed")
        
        # Disconnect
        client.disconnect()
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if client.connected:
            client.disconnect()

if __name__ == "__main__":
    test()
