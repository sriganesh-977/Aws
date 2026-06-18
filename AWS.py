import boto3
import base64
import csv
import io
import time
from datetime import datetime, timezone

def generate_and_get_credential_report(iam_client):
    """Generates and downloads the latest AWS IAM credential report."""
    print("[*] Requesting IAM Credential Report...")
    while True:
        response = iam_client.generate_credential_report()
        if response['State'] == 'COMPLETE':
            print("[+] Credential Report generated successfully.")
            break
        print("[*] Report generating, waiting 2 seconds...")
        time.sleep(2)
        
    report_response = iam_client.get_credential_report()
    # The report content is base64 encoded CSV
    csv_content = base64.b64decode(report_response['Content']).decode('utf-8')
    return csv_content

def calculate_age_days(date_str):
    """Calculates age in days from an AWS ISO8601 date string."""
    if date_str in ['N/A', 'no_information', 'not_supported']:
        return None
    # Handle both Z and offset formats if present
    date_str = date_str.replace('Z', '+00:00')
    dt = datetime.fromisoformat(date_str)
    now = datetime.now(timezone.utc)
    return (now - dt).days

def audit_iam_data(csv_content):
    """Parses the credential report and runs security audit checks."""
    csv_reader = csv.DictReader(io.StringIO(csv_content))
    
    findings = {
        "root_mfa_disabled": False,
        "root_active_keys": False,
        "users_missing_mfa": [],
        "stale_passwords": [], # > 90 days
        "stale_access_keys": [], # > 90 days
        "unused_credentials": [] # no login/use > 90 days
    }
    
    for row in csv_reader:
        user_name = row['user']
        
        # 1. Root User Checks
        if user_name == '<root_account>':
            if row['mfa_active'] == 'false':
                findings["root_mfa_disabled"] = True
            if row['access_key_1_active'] == 'true' or row['access_key_2_active'] == 'true':
                findings["root_active_keys"] = True
            continue
            
        # 2. MFA Check for IAM Users
        if row['password_enabled'] == 'true' and row['mfa_active'] == 'false':
            findings["users_missing_mfa"].append(user_name)
            
        # 3. Password Age Check
        pwd_last_changed = calculate_age_days(row['password_last_changed'])
        if pwd_last_changed and pwd_last_changed > 90:
            findings["stale_passwords"].append(f"{user_name} ({pwd_last_changed} days old)")
            
        # 4. Access Key Rotation Check
        for key_num in ['1', '2']:
            if row[f'access_key_{key_num}_active'] == 'true':
                key_age = calculate_age_days(row[f'access_key_{key_num}_last_rotated'])
                if key_age and key_age > 90:
                    findings["stale_access_keys"].append(f"{user_name} (Key {key_num}: {key_age} days old)")

        # 5. Unused Identity Check (No activity in 90 days)
        last_login = calculate_age_days(row['password_last_used'])
        key1_use = calculate_age_days(row['access_key_1_last_used'])
        key2_use = calculate_age_days(row['access_key_2_last_used'])
        
        ages = [a for a in [last_login, key1_use, key2_use] if a is not None]
        if ages and all(age > 90 for age in ages):
            findings["unused_credentials"].append(user_name)

    return findings

def print_audit_report(findings):
    """Formats and prints the findings as a clean security report."""
    print("\n" + "="*50)
    print("           AWS IAM SECURITY AUDIT REPORT          ")
    print("="*50)
    
    print("\n## 🚨 CRITICAL SEVERITY")
    if findings["root_mfa_disabled"]:
        print("[-] FAIL: Root account does NOT have MFA enabled!")
    else:
        print("[+] PASS: Root account MFA is enabled.")
        
    if findings["root_active_keys"]:
        print("[-] FAIL: Root account has active Access Keys!")
    else:
        print("[+] PASS: Root account has no active Access Keys.")

    print("\n## 🔴 HIGH SEVERITY: Missing MFA")
    if findings["users_missing_mfa"]:
        for user in findings["users_missing_mfa"]:
            print(f"[-] FAIL: User '{user}' has console access but MFA is disabled.")
    else:
        print("[+] PASS: All active console users have MFA enabled.")

    print("\n## 🟡 MEDIUM SEVERITY: Credential Age (>90 Days)")
    print(f"[*] Stale Passwords: {findings['stale_passwords'] if findings['stale_passwords'] else 'None'}")
    print(f"[*] Stale Access Keys: {findings['stale_access_keys'] if findings['stale_access_keys'] else 'None'}")

    print("\n## 🔵 LOW SEVERITY: Clean-up Opportunities")
    print(f"[*] Unused Identities (>90 days inactive): {findings['unused_credentials'] if findings['unused_credentials'] else 'None'}")
    print("\n" + "="*50)

if __name__ == "__main__":
    # Initialize IAM Client
    iam_client = boto3.client('iam')
    
    try:
        csv_data = generate_and_get_credential_report(iam_client)
        audit_results = audit_iam_data(csv_data)
        print_audit_report(audit_results)
    except Exception as e:
        print(f"[!] Audit failed: {e}")