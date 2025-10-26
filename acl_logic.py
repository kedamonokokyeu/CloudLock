import boto3
from datetime import datetime
from botocore.exceptions import ClientError
import csv
import re
from web_scraper import WebLeakDetector

def check_bucket(s3_client, bucket_name):
    """
    Check public/private with ACL
    s3 is boto3 s3 client
    bucket_name is name of s3 bucket to check
    """
    try:
        acl_response = s3_client.get_bucket_acl(Bucket = bucket_name) # gets the bucket's access control list
        for grant in acl_response.get('Grants', []): # iterate through each rule in Grants
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            
            #see who has access
            #uniform resource identifier (uri) is unique id of each
            grantee_uri = grantee.get('URI', '') # AWS identifies grantees by a URI
            
            # check public access uri
            # allusers is anyone on internet
            # authenticatedusers is any AWS account holder
            
            if grantee_uri in ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']: # using the URI, check if it applies to a public group
                if permission in ['READ', 'WRITE', 'FULL_CONTROL', 'READ_ACP', 'WRITE_ACP']:
                    print(f"PUBLIC ACCESS DETECTED!")
                    print(f"Grantee: {grantee_uri.split('/')[-1]}")
                    print(f"Permission: {permission}")
                    return 'Public/Non-Compliant'
                
        return 'Private/Compliant' #no public access found
    
    except ClientError as e: 
        error_code = e.response['Error']['Code']
        print(f"Error checking ACL: {error_code}")
        return f'Error: {error_code}'
    
def check_bucket_encryption(s3_client, bucket_name):
    # check if encryption enabled
    try:
        # if succeeds, encryption is on
        s3_client.get_bucket_encryption(Bucket = bucket_name)
        return 'Enabled/Compliant'
    except ClientError as e:
        error_code = e.response['Error']['Code']
        # this specific error means encryption is not configured
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            return 'Disabled/Non-Compliant'
        
        # Some other error occurred
        return f'Error: {error_code}'

def check_bucket_logging(s3_client, bucket_name):
    # check if logging enabled
    try:
        response = s3_client.get_bucket_logging(Bucket = bucket_name)
        if 'LoggingEnabled' in response:
            return 'Enabled/Compliant'
        else:
            return 'Disabled/Non-Compliant'
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return f"Error: {error_code}"
    
    
def check_bucket_versioning(s3_client, bucket_name):
    # check if versioning enabled
    try:
        response = s3_client.get_bucket_versioning(Bucket = bucket_name)
        status = response.get('Status', 'Disabled')
        
        if status == 'Enabled':
            return 'Enabled/Compliant'
        else:
            return 'Disabled/Non-Compliant'
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return f"Error: {error_code}"

def check_bucket_lifecycle(s3_client, bucket_name):
    # check if lifecycle enabled
    try:
        s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        return 'Configured'
    
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
            return 'Not Configured'
        return f'Error: {e.response
                         ["Error"]["Code"]}'

def safe_get_bucket_tags(s3_client, bucket_name): # so we can access tags for risk valuation later and also to prevent untagged buckets
    try:
        response = s3_client.get_bucket_tagging(Bucket = bucket_name)
        return response.get("TagSet", []) # if no TagSet, return empty list
    
    except ClientError as e:
        code = e.response["Error"]["Code"] # 'Error' is the outer dictionary, 'Code' is the inner dictionary that we want from 'Error'
        if code in ["NoSuchTagSet", "AccessDenied", "NotImplemented"]:
            print(f"Tags not available for {bucket_name} ({code})")
            return []
        else:
            print(f"Unexpected tag error for {bucket_name}: {code}")
            return []

def check_compliance_score(bucket_data):
    
    score = 0
    # ACL Status (25 points)
    if 'Compliant' in bucket_data['ACL_Status']:
        score += 25
    
    # Encryption Status (25 points)
    if 'Compliant' in bucket_data['Encryption_Status']:
        score += 25
    
    # Logging Status (25 points)
    if 'Compliant' in bucket_data['Logging_Status']:
        score += 25
    
    # Versioning Status (25 points)
    if 'Compliant' in bucket_data['Versioning_Status']:
        score += 25
    
    return score
        
def infer_sensitivity(bucket_name, tags = None):
    score = 0
    name_lower = bucket_name.lower()

    if any(k in name_lower for k in ["prod", "finance", "customer", "key", "private", "passwords", "confidential"]):
        score += 0.4

    if tags:
        for tag in tags:
            key = tag['Key'].lower()
            val = tag.get('Value', '').lower()

            if any(word in key for word in ["sensitivity", "confidential", "pii", "secret"]):
                if val in ["high", "critical", "confidential"]:
                    score += 0.4
                elif val in ["medium", "internal"]:
                    score += 0.2
                elif val in ["low", "public"]:
                    score += 0

    return min(score, 1.0)
            

def audit_all_buckets(user_role_arn = None, demo_buckets = None):
    if user_role_arn:
        # --- REAL AWS MODE ---
        s3_client = get_s3_client_with_assumed_role(user_role_arn)
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
    else:
        # --- DEMO MODE ---
        print("Demo mode enabled")
        s3_client = boto3.client("s3", region_name="us-west-2")

        if demo_buckets:
            print(f"Using {len(demo_buckets)} provided demo bucket(s)")
            buckets = [
                {"Name": name, "CreationDate": datetime.now()}
                for name in demo_buckets.values()
            ]
        else:
            print("No demo buckets provided. Creating demo environment...")
            from demo_setup import create_demo_buckets
            demo_buckets = create_demo_buckets()
            buckets = [
                {"Name": name, "CreationDate": datetime.now()}
                for name in demo_buckets.values()
            ]

    results = []
    
    # loop that performs all 5 checks
    for index, bucket in enumerate(buckets, 1):
        # bucket is dictionary
        bucket_name = bucket['Name']
    
        # progress bar
        print(f"[{index}/{len(buckets)}] Auditing: {bucket_name}")
        
        bucket_data = {'Bucket_Name' : bucket_name, 'Creation_Date' : bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')}
        # ACL Status (Public/Private)
        print(f"Checking ACL...")  # NEW: Progress indicator
        bucket_data['ACL_Status'] = check_bucket(s3_client, bucket_name)
        
        # Encryption
        print(f"Checking Encryption...")
        bucket_data['Encryption_Status'] = check_bucket_encryption(s3_client, bucket_name)
        
        # Logging
        print(f"Checking Logging...")
        bucket_data['Logging_Status'] = check_bucket_logging(s3_client, bucket_name)
        
        # Versioning
        print(f"Checking Versioning...")
        bucket_data['Versioning_Status'] = check_bucket_versioning(s3_client, bucket_name)
        
        # Lifecycle Policies (Optional)
        print(f"Checking Lifecycle Policies...")
        bucket_data['Lifecycle_Policy'] = check_bucket_lifecycle(s3_client, bucket_name)
        
        # Calculate compliance score
        bucket_data['Compliance_Score'] = check_compliance_score(bucket_data)
    
        # check bucket ACL status
        # acl_status = check_bucket(s3_client, bucket_name)
    
        
        score = bucket_data['Compliance_Score']
        if score == 100:
            bucket_data['Overall_Status'] = 'FULLY COMPLIANT'
        elif score >= 75:
            bucket_data['Overall_Status'] = 'MOSTLY COMPLIANT'
        elif score >= 50:
            bucket_data['Overall_Status'] = 'PARTIALLY COMPLIANT'
        else:
            bucket_data['Overall_Status'] = 'NON-COMPLIANT'
            
            
        print(f"Compliance Score: {score}/100")
        tags = safe_get_bucket_tags(s3_client, bucket_name)
        sensitivity_score = infer_sensitivity(bucket_name, tags)
        bucket_data['Sensitivity'] = int(sensitivity_score * 10) + 1
    
        print(f"Sensitivity: {bucket_data['Sensitivity']}/10")
        print(f"{bucket_data['Overall_Status']}")
        print()
        
        
        # store result
        results.append(bucket_data)
    #web scrape
    print("\n" + "="*50)
    print("STARTING EXTERNAL LEAK DETECTION")
    print("="*50)

    bucket_names = [r['Bucket_Name'] for r in results]
    leak_detector = WebLeakDetector()
    leak_results = leak_detector.scan_all_buckets(bucket_names)
    
    for i, result in enumerate(results):
        leak_info = leak_results[i]
        result['External_Leaks'] = 'DETECTED' if leak_info['leaks_found'] else 'NONE'
        result['Leak_Severity'] = leak_info['severity']
        result['Leak_Sources'] = len(leak_info['sources'])
    
    """
        # display status
        if acl_status == 'Private':
            print(f"Status: {acl_status}")
            print()
        elif acl_status == 'True':
            print(f"Status: {acl_status} - NEED ATTENTION")
            print()
        else:
            print(f"Status: {acl_status} - ERROR")
    """
        
    print('=' * 30)
    print("SUMMARY:")
    print('=' * 30)

    # count of summary stats
    total = len(results)
    fully_compliant = sum(1 for r in results if r['Compliance_Score'] == 100)
    mostly_compliant = sum(1 for r in results if 75 <= r['Compliance_Score'] < 100)
    partially_compliant = sum(1 for r in results if 50 <= r['Compliance_Score'] < 75)
    non_compliant = sum(1 for r in results if r['Compliance_Score'] < 50)
    
    avg_score = sum(r['Compliance_Score'] for r in results) / total if total > 0 else 0
    
    # Calculate sensitivity (0.0-1.0 scale, converted to 1-10)
    
    # display summary
    print()
    print(f"Total Buckets Audited: {total}")
    print(f"Average Compliance Score: {avg_score:.1f}/100\n")
    
    print(f"Fully Compliant (100/100): {fully_compliant}")
    print(f"Mostly Compliant (75-99/100): {mostly_compliant}")
    print(f"Partially Compliant (50-74/100): {partially_compliant}")
    print(f"Non-Compliant (0-49/100): {non_compliant}")
    print()
    
    print("DETAILED BREAKDOWN:")
    print("=" * 30)
    
    # ACL compliance
    acl_compliant = sum(1 for r in results if 'Compliant' in r['ACL_Status'])
    print(f"Private/Secure ACLs: {acl_compliant}/{total} buckets")
    
    # encryption compliance
    enc_compliant = sum(1 for r in results if 'Compliant' in r['Encryption_Status'])
    print(f"Encryption Enabled: {enc_compliant}/{total} buckets")
    
    # logging compliance
    log_compliant = sum(1 for r in results if 'Compliant' in r['Logging_Status'])
    print(f"Logging Enabled: {log_compliant}/{total} buckets")
    
    # versioning compliance
    ver_compliant = sum(1 for r in results if 'Compliant' in r['Versioning_Status'])
    print(f"Versioning Enabled: {ver_compliant}/{total} buckets")
    
    # lifecycle policies
    life_configured = sum(1 for r in results if r['Lifecycle_Policy'] == 'Configured')
    print(f"Lifecycle Policies: {life_configured}/{total} buckets (optional)")
    
   
    
    print()
    print("COMPLIANCE PERCENTAGES:")
    print("-" * 30)
    
    acl_percentage = (acl_compliant/total * 100) if total > 0 else 0
    enc_percentage = (enc_compliant/total * 100) if total > 0 else 0
    log_percentage = (log_compliant/total * 100) if total > 0 else 0
    ver_percentage = (ver_compliant/total * 100) if total > 0 else 0
    
    print(f"ACL Compliance: {acl_percentage:.1f}% ({acl_compliant}/{total})")
    print(f"Encryption Compliance: {enc_percentage:.1f}% ({enc_compliant}/{total})")
    print(f"Logging Compliance: {log_percentage:.1f}% ({log_compliant}/{total})")
    print(f"Versioning Compliance: {ver_percentage:.1f}% ({ver_compliant}/{total})")
    
    print()
    print("BUCKETS THAT NEED ATTENTION:")
    print("-" * 30)
    
    # Find all non-compliant buckets (score < 100)
    non_compliant_buckets = [r for r in results if r['Compliance_Score'] < 100]
    
    if len(non_compliant_buckets) == 0:
        print("All buckets are fully compliant! Great job!")
    else:
        for bucket in non_compliant_buckets:
            print(f"\n{bucket['Bucket_Name']} - Score: {bucket['Compliance_Score']}/100")
            
            # Show what needs to be fixed
            issues = []
            if 'Non-Compliant' in bucket['ACL_Status']:
                issues.append("ACL: Bucket is PUBLIC - restrict access immediately!")
            if 'Non-Compliant' in bucket['Encryption_Status']:
                issues.append("Encryption: Data not encrypted at rest")
            if 'Non-Compliant' in bucket['Logging_Status']:
                issues.append("Logging: Access logs not enabled")
            if 'Non-Compliant' in bucket['Versioning_Status']:
                issues.append("Versioning: File versioning not enabled")
            
            for issue in issues:
                print(f" {issue}")
    
    print("\n" + "=" * 30)
    
    # Return results for export
    return results
"""
def export_to_csv(audit_results, filename=None):
    # 
    Export results into a csv
    Able to put it into Excel/Google Sheets and then it is human readable
    #
 
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'soc2_s3_audit_report_{timestamp}.csv'
    
    audit_date = datetime.now().strftime('A%Y-%m-%d')
    auditor_version = "AUDITOR v.1.0"
    
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()['Account']
    # summary metrics
    total_buckets = len(audit_results)
    passed_buckets = sum(1 for r in audit_results if r['Compliance_Score'] == 100)
    failed_buckets = total_buckets - passed_buckets
    public_buckets = sum(1 for r in audit_results if 'Public' in r['ACL_Status'])
    unencrypted_buckets = sum(1 for r in audit_results if 'Disabled' in r['Encryption_Status'])
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Header section
        
        writer.writerow(['', 'SOC 2 S3 Bucket Audit Report', '', '', '', ''])
        writer.writerow([])
        writer.writerow(['Date:', '', audit_date, '', '', ''])
        writer.writerow(['Auditor:', '', auditor_version, '', '', ''])
        writer.writerow(['AWS Account ID:', '', account_id, '', '', ''])
        writer.writerow(['Region:', '', 'us-west-2', '', '', ''])
        writer.writerow([])
        
        # Table headers
        
        writer.writerow(['BucketName', 'Encryption', 'Versioning', 'Logging', 'ACL', 'Public Access', 'Sensitivity', 'External Leaks', 'Leak Severity'])
        for bucket in audit_results:
            bucket_name = bucket['Bucket_Name']
            
            # scraping
            external_leaks = 'DETECTED' if bucket.get('External_Leaks') == 'DETECTED' else 'None'
            leak_severity = bucket.get('Leak_Severity', 'N/A')
            
            # format encryption status
            encryption = 'Enabled' if 'Compliant' in bucket['Encryption_Status'] else 'Disabled'
            
            # format versioning status
            versioning = 'Enabled' if 'Compliant' in bucket['Versioning_Status'] else 'Disabled'
            
            # format logging status
            if 'Compliant' in bucket['Logging_Status']:
                logging = bucket['Logging_Status'].split('/')[0] 
            else:
                logging = 'Not Configured'
            acl = 'Private' if 'Compliant' in bucket['ACL_Status'] else bucket['ACL_Status'].split('/')[0]
            
            # public access indicator
            public_access = 'Yes' if 'Public' in bucket['ACL_Status'] else 'No'
            
            # get sensitivity from bucket data (1-10 risk score)
            sensitivity = bucket.get('Sensitivity', 'N/A')
            
            writer.writerow([
                bucket_name,
                encryption,
                versioning,
                logging,
                acl,
                public_access,
                sensitivity,
                external_leaks,
                leak_severity
            ])
        writer.writerow([])
        writer.writerow(['Metric', 'Count'])
        writer.writerow(['Total Buckets', total_buckets])
        writer.writerow(['Passed Buckets', passed_buckets])
        writer.writerow(['Failed Buckets', failed_buckets])
        writer.writerow(['Public Buckets', public_buckets])
        writer.writerow(['Unencrypted Buckets', unencrypted_buckets])
    print(f"\nCSV report exported to: {filename}")
    return filename
"""
def format_csv_field(status_string):

    # Helper function to format the status string for the CSV.
    # Returns 'Enabled', 'Disabled', 'Not Configured', or 'Error'.
 
    if 'Compliant' in status_string:
        return status_string.split('/')[0]  # 'Enabled'
    elif 'Non-Compliant' in status_string:
        # 'Disabled' or 'Public'
        status = status_string.split('/')[0]
        return 'Not Configured' if status == 'Disabled' else status
    elif 'Error' in status_string:
        return 'Error' # You could also return the full error: status_string
    elif status_string == 'Not Configured':
         return 'Not Configured'
    else:
        return 'Unknown'
def export_to_csv(audit_results, filename=None):
    """
    Export results into a csv
    Able to put it into Excel/Google Sheets and then it is human readable
    """
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'soc2_s3_audit_report_{timestamp}.csv'
    
    audit_date = datetime.now().strftime('%Y-%m-%d')
    auditor_version = "AUDITOR v.1.0"
    
    # Mock STS client and Account ID for demo mode
    try:
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
    except Exception as e:
        print("Could not get AWS Account ID (demo mode?). Using '123456789012'.")
        account_id = '123456789012' # Mock account ID
        
    # summary metrics
    total_buckets = len(audit_results)
    passed_buckets = sum(1 for r in audit_results if r['Compliance_Score'] == 100)
    failed_buckets = total_buckets - passed_buckets
    public_buckets = sum(1 for r in audit_results if 'Public' in r['ACL_Status'])
    unencrypted_buckets = sum(1 for r in audit_results if 'Disabled' in r['Encryption_Status'])
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Header section
        
        writer.writerow(['', 'SOC 2 S3 Bucket Audit Report', '', '', '', ''])
        writer.writerow([])
        writer.writerow(['Date:', '', audit_date, '', '', ''])
        writer.writerow(['Auditor:', '', auditor_version, '', '', ''])
        writer.writerow(['AWS Account ID:', '', account_id, '', '', ''])
        writer.writerow(['Region:', '', 'us-west-2', '', '', ''])
        writer.writerow([])
        
        # Table headers
        
        writer.writerow(['BucketName', 'Encryption', 'Versioning', 'Logging', 'ACL', 'Public Access', 'Sensitivity', 'External Leaks', 'Leak Severity'])
        for bucket in audit_results:
            bucket_name = bucket['Bucket_Name']
            
            # scraping
            external_leaks = 'DETECTED' if bucket.get('External_Leaks') == 'DETECTED' else 'None'
            leak_severity = bucket.get('Leak_Severity', 'N/A')
            
            # --- START: FIXED LOGIC ---
            
            # Use the helper function for clean formatting
            encryption = format_csv_field(bucket['Encryption_Status'])
            versioning = format_csv_field(bucket['Versioning_Status'])
            logging = format_csv_field(bucket['Logging_Status'])
            acl = format_csv_field(bucket['ACL_Status']) # Will be 'Private' or 'Public' or 'Error'

            # --- END: FIXED LOGIC ---
            
            # public access indicator
            public_access = 'Yes' if 'Public' in bucket['ACL_Status'] else 'No'
            
            # get sensitivity from bucket data (1-10 risk score)
            sensitivity = bucket.get('Sensitivity', 'N/A')
            
            writer.writerow([
                bucket_name,
                encryption,
                versioning,
                logging,
                acl,
                public_access,
                sensitivity,
                external_leaks,
                leak_severity
            ])
        writer.writerow([])
        writer.writerow(['Metric', 'Count'])
        writer.writerow(['Total Buckets', total_buckets])
        writer.writerow(['Passed Buckets', passed_buckets])
        writer.writerow(['Failed Buckets', failed_buckets])
        writer.writerow(['Public Buckets', public_buckets])
        writer.writerow(['Unencrypted Buckets', unencrypted_buckets])
    print(f"\nCSV report exported to: {filename}")
    return filename

def get_s3_client_with_assumed_role(user_role_arn):
    # explicitly specify the region for STS
    sts_client = boto3.client('sts', region_name='us-west-2')

    response = sts_client.assume_role(
        RoleArn = user_role_arn,
        RoleSessionName = "AuditSession",
        ExternalId="cloudlock-audit-verify"
    )

    creds = response["Credentials"]

    # explicitly specify region again for S3
    return boto3.client(
        's3',
        region_name='us-west-2',
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

if __name__ == "__main__":
    user_role_arn = input("Enter the AWS Role ARN to audit (or press Enter for demo mode): ").strip()

    if not user_role_arn:
        print("\n Running in demo mode...")
        #FOR DEMO
        from demo_setup import create_demo_buckets

        demo_buckets = create_demo_buckets()
        audit_results = audit_all_buckets(demo_buckets=demo_buckets)

        if audit_results:
            export_to_csv(audit_results, filename="soc2_demo_audit_report.csv")
            print("\n Demo audit complete! File saved as soc2_demo_audit_report.csv")
        else:
            print("\n No results generated during demo mode.")

    else:

        if not re.match(r"^arn:aws:iam::\d{12}:role\/[\w+=,.@\-_/]+$", user_role_arn):
            print(" Invalid Role ARN format. It should look like:")
            print("   arn:aws:iam::<account-id>:role/<role-name>")
            exit(1)

        #FOR REAL BUCKETS WITH PERSONAL AWS CONNECTION
        print(f"\n Auditing AWS account via role: {user_role_arn}")
        audit_results = audit_all_buckets(user_role_arn=user_role_arn)

        if audit_results:
            export_to_csv(audit_results)
            print("\n Full audit completed successfully!")
        else:
            print("\n No audit results were generated.")


    