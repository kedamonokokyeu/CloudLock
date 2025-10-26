
import boto3
from acl_logic import audit_all_buckets, export_to_csv

print("Starting audit script...")

try:
    # Assume the audit role
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn="arn:aws:iam::647743454463:role/S3_Audit_Role_Test",
        RoleSessionName="AuditSession"
    )

    creds = response["Credentials"]

    print("✓ Successfully assumed role")
    print(f"✓ Account ID: {response['AssumedRoleUser']['Arn'].split(':')[4]}")
    print()

    # Run the audit (audit_all_buckets will create its own S3 client)
    # The boto3 credentials are automatically used from the environment
    # after assume_role sets them
    
    import os
    os.environ['AWS_ACCESS_KEY_ID'] = creds["AccessKeyId"]
    os.environ['AWS_SECRET_ACCESS_KEY'] = creds["SecretAccessKey"]
    os.environ['AWS_SESSION_TOKEN'] = creds["SessionToken"]
    
    audit_results = audit_all_buckets()
    
    if audit_results:
        export_to_csv(audit_results)
        print("\n✓ Audit completed successfully!")
    else:
        print("\n⚠️ No results to export")

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
