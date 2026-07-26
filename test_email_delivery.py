#!/usr/bin/env python3
"""
Smart Banking & AI Fraud Detection System
Safe Email Delivery Diagnostic Script

Usage:
    python test_email_delivery.py [recipient_email]

Example:
    python test_email_delivery.py user@example.com
"""

import sys
import os
import urllib.request
import urllib.error
import json
import re

def is_valid_email(email):
    if not email:
        return False
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(regex, email))

def main():
    print("====================================================")
    print("Smart Banking - Resend Email Delivery Diagnostic")
    print("====================================================")

    # 1. Inspect Environment Variables safely (Never print secrets)
    resend_api_key = os.environ.get('RESEND_API_KEY')
    resend_from = os.environ.get('RESEND_FROM_EMAIL', 'onboarding@resend.dev')
    is_render = bool(os.environ.get('RENDER'))

    print(f"Environment Mode    : {'RENDER (Production)' if is_render else 'LOCAL (Development)'}")
    print(f"RESEND_API_KEY State: {'CONFIGURED (Key present)' if resend_api_key else 'MISSING (Not set)'}")
    print(f"RESEND_FROM_EMAIL   : {resend_from}")
    print("----------------------------------------------------")

    if not resend_api_key:
        print("\n[DIAGNOSTIC STATUS]: RESEND_API_KEY environment variable is NOT set.")
        if not is_render:
            print("In local development, the application falls back to [DEBUG MOCK EMAIL] stdout logs.")
            print("To test real email delivery, set RESEND_API_KEY in your environment:")
            print("  set RESEND_API_KEY=re_your_api_key_here  (Windows CMD)")
            print("  $env:RESEND_API_KEY=\"re_your_api_key_here\"  (PowerShell)")
        else:
            print("On Render production, missing RESEND_API_KEY will block email delivery safely.")
        sys.exit(1)

    # 2. Obtain Recipient Email
    if len(sys.argv) > 1:
        recipient = sys.argv[1].strip()
    else:
        recipient = input("\nEnter recipient email address to test: ").strip()

    if not is_valid_email(recipient):
        print(f"\n[ERROR] Invalid recipient email format: '{recipient}'")
        sys.exit(1)

    print(f"\nSending test email to: {recipient}...")

    # 3. Construct Resend HTTPS Request
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {resend_api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "from": resend_from,
        "to": [recipient],
        "subject": "Smart Banking - Email Transport Test",
        "text": "Hello!\n\nThis is a diagnostic test email sent from your Smart Banking & AI Fraud Detection System via Resend HTTPS API.\n\nIf you received this message, your email delivery transport is fully functional!\n\nRegards,\nSmart Banking Security Team",
        "html": "<div style='font-family: Arial, sans-serif; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; max-width: 500px;'><h2 style='color: #4a3b56;'>Smart Banking Email Test</h2><p>This is a diagnostic test email sent from your <strong>Smart Banking & AI Fraud Detection System</strong> via Resend HTTPS API.</p><p style='color: #27ae60; font-weight: bold;'>✓ Email delivery transport is fully functional!</p></div>"
    }

    # 4. Perform HTTPS Request
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers=headers,
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10.0) as response:
            res_body = response.read().decode('utf-8')
            res_json = json.loads(res_body)
            print("\n====================================================")
            print("RESULT: SUCCESS (HTTP Status 200 OK)")
            print(f"Resend Message ID : {res_json.get('id', 'N/A')}")
            print("Status            : Resend accepted email for delivery!")
            print("====================================================")

            if resend_from == 'onboarding@resend.dev':
                print("\n[NOTE ON RESEND RESTRICTIONS]:")
                print("Your RESEND_FROM_EMAIL is currently set to 'onboarding@resend.dev'.")
                print("Resend free tier permits sending ONLY to the email address registered with your Resend account.")
                print("If sending to other arbitrary domain addresses fails with 403 Forbidden,")
                print("you must add and verify a custom domain in the Resend dashboard.")

    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        print("\n====================================================")
        print(f"RESULT: FAILED (HTTP Status {e.code})")
        try:
            err_json = json.loads(err_body)
            err_msg = err_json.get('message', err_body)
            err_name = err_json.get('name', 'API_Error')
            print(f"Error Type    : {err_name}")
            print(f"Error Message : {err_msg}")
        except Exception:
            print(f"Error Details : {err_body}")
        print("====================================================")

        if e.code == 403 and "only send testing emails" in err_body:
            print("\n[EXACT CAUSE DETECTED]:")
            print("Resend rejected delivery because RESEND_FROM_EMAIL is 'onboarding@resend.dev'.")
            print("With 'onboarding@resend.dev', Resend ONLY allows emails to be sent to your own Resend account email.")
            print("To send OTP emails to any user address:")
            print(" 1. Add and verify your custom domain in Resend Dashboard (https://resend.com/domains)")
            print(" 2. Set environment variable: RESEND_FROM_EMAIL=\"otp@yourdomain.com\"")

    except urllib.error.URLError as e:
        print("\n====================================================")
        print(f"RESULT: NETWORK ERROR")
        print(f"Details: {e.reason}")
        print("====================================================")

    except Exception as e:
        print("\n====================================================")
        print(f"RESULT: UNEXPECTED ERROR")
        print(f"Details: {str(e)}")
        print("====================================================")

if __name__ == '__main__':
    main()
