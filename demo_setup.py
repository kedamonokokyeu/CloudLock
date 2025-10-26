import boto3
from botocore.exceptions import ClientError
import time
import random
import json
from datetime import datetime   
from acl_logic import audit_all_buckets



def create_demo_buckets():
    """
    Creates demo S3 buckets for auditing tests:
    - One encrypted & private bucket (fully compliant)
    - One unencrypted & public bucket (non-compliant)
    - One logging target bucket
    """
    s3 = boto3.client('s3')
    suffix = str(random.randint(1000000000, 9999999999))

    buckets = {
        "encrypted": f"soc3-demo-encrypted-{suffix}",
        "unencrypted": f"soc3-demo-unencrypted-{suffix}",
        "logging": f"soc3-demo-logging-{suffix}"
    }

    print("Creating demo buckets...")
    for b in buckets.values():
        try:
            s3.create_bucket(
                Bucket=b,
                CreateBucketConfiguration={"LocationConstraint": "us-west-2"}
            )
            print(f"Created: {b}")
        except ClientError as e:
            print(f"Error creating {b}: {e}")

    time.sleep(2)

    # Enable encryption for encrypted bucket
    try:
        s3.put_bucket_encryption(
            Bucket=buckets["encrypted"],
            ServerSideEncryptionConfiguration={
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                }]
            }
        )
        print(f"Encryption enabled for: {buckets['encrypted']}")
    except ClientError as e:
        print(f"Error enabling encryption: {e}")

    # Enable versioning on encrypted bucket
    try:
        s3.put_bucket_versioning(
            Bucket=buckets["encrypted"],
            VersioningConfiguration={"Status": "Enabled"}
        )
        print(f"🌀 Versioning enabled for: {buckets['encrypted']}")
    except ClientError as e:
        print(f"Error enabling versioning: {e}")

    # Enable logging from unencrypted -> logging bucket
    try:
        s3.put_bucket_logging(
            Bucket=buckets["unencrypted"],
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": buckets["logging"],
                    "TargetPrefix": "logs/"
                }
            }
        )
        print(f"Logging from {buckets['unencrypted']} → {buckets['logging']}")
    except ClientError as e:
        print(f"Error enabling logging: {e}")

    # Make unencrypted bucket PUBLIC for ACL test
    try:
        s3.put_bucket_acl(
            Bucket=buckets["unencrypted"],
            ACL="public-read"
        )
        print(f"Made {buckets['unencrypted']} PUBLIC (ACL = public-read)")
    except ClientError as e:
        print(f"Error making bucket public: {e}")

    # Add lifecycle policy to encrypted bucket
    try:
        s3.put_bucket_lifecycle_configuration(
            Bucket=buckets["encrypted"],
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "ExpireOldVersions",
                        "Filter": {"Prefix": ""},
                        "Status": "Enabled",
                        "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
                    }
                ]
            }
        )
        print(f"Lifecycle policy added to: {buckets['encrypted']}")
    except ClientError as e:
        print(f"Error adding lifecycle policy: {e}")

    # Add tags for sensitivity scoring
    try:
        s3.put_bucket_tagging(
            Bucket=buckets["encrypted"],
            Tagging={"TagSet": [{"Key": "sensitivity", "Value": "high"}]}
        )
        s3.put_bucket_tagging(
            Bucket=buckets["unencrypted"],
            Tagging={"TagSet": [{"Key": "env", "Value": "public-demo"}]}
        )
        print("Tags applied to buckets")
    except ClientError as e:
        print(f"Error tagging buckets: {e}")

    print("\n Demo environment ready for audit.")
    return buckets

def export_demo_buckets_to_json(buckets):

    bucket_list = {
        "Buckets": [
            {"Name": name, "CreationDate": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
            for name in buckets.values()
        ],
        "Region": "us-west-2",
        "AccountId": "647743454463"
    }

    filename = "demo_buckets.json"
    with open(filename, "w") as f:
        json.dump(bucket_list, f, indent=2)
    print(f"\n Demo bucket list exported to: {filename}")

    return filename


if __name__ == "__main__":
    buckets = create_demo_buckets()
    export_demo_buckets_to_json(buckets)