from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import os
from datetime import datetime
from acl_logic import audit_all_buckets, export_to_csv
from botocore.exceptions import ClientError
import boto3
import csv
from web_scraper import WebLeakDetector

app = Flask(__name__)
CORS(app)

# === GLOBALS ===
audit_cache = {}
REPORTS_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# === UPLOAD ENDPOINT ===
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # --- handle JSON uploads ---
        if file.filename.endswith('.json'):
            data = json.load(file)
            demo_buckets = {
                b["Name"].split('-')[2]: b["Name"]
                for b in data.get("Buckets", [])
            }

            print(" Running offline audit from uploaded JSON...")
            audit_results = audit_all_buckets(demo_buckets=demo_buckets)

        # --- handle CSV uploads (optional future feature) ---
        elif file.filename.endswith('.csv'):
            print(" CSV file uploaded (not used for audit yet).")
            audit_results = []

        else:
            return jsonify({'error': 'Invalid file type. Use JSON or CSV'}), 400

        if not audit_results:
            return jsonify({'error': 'No audit results generated'}), 500

        # --- export to CSV ---
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'soc2_s3_audit_report_{timestamp}.csv'
        filepath = os.path.join(REPORTS_DIR, filename)
        export_to_csv(audit_results, filename=filepath)
        audit_cache[filename] = audit_results

        # --- run leak detection ---
        bucket_names = [r['Bucket_Name'] for r in audit_results]
        detector = WebLeakDetector()
        leak_results = detector.scan_all_buckets(bucket_names)

        for i, result in enumerate(audit_results):
            if i < len(leak_results):
                result['External_Leaks'] = 'DETECTED' if leak_results[i]['leaks_found'] else 'NONE'
                result['Leak_Severity'] = leak_results[i]['severity']

        print(f" Audit complete → saved to {filepath}")

        return jsonify({
            'message': 'Audit completed successfully',
            'filename': filename,
            'total_buckets': len(audit_results),
            'compliant': sum(1 for r in audit_results if r['Compliance_Score'] == 100),
            'download_url': f'/download/{filename}'
        }), 200

    except Exception as e:
        print(f" Error: {str(e)}")
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# === DOWNLOAD ENDPOINT ===
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        filepath = os.path.join(REPORTS_DIR, filename)
        return send_file(filepath, mimetype='text/csv', as_attachment=True, download_name=filename)
    except Exception as e:
        print(f" Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# === HEALTH ENDPOINT ===
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({'status': 'healthy'}), 200


# === AWS CONNECTION ENDPOINT ===
@app.route("/connect-aws", methods=["POST"])
def connect_aws():
    try:
        data = request.get_json(silent=True) or {}
        role_arn = data.get("role_arn")

        # --- AWS Authentication ---
        if role_arn:
            sts = boto3.client("sts")
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="CloudLockAuditSession",
                ExternalId="cloudlock-verify"
            )
            creds = assumed["Credentials"]
            s3 = boto3.client(
                "s3",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
        else:
            # Use default credentials (local ~/.aws)
            s3 = boto3.client("s3")

        buckets = s3.list_buckets()["Buckets"]
        results = []

        # --- Bucket checks ---
        for b in buckets:
            name = b["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
                enc = "✓ Enabled"
            except ClientError:
                enc = "✗ Disabled"

            ver = s3.get_bucket_versioning(Bucket=name)
            ver_status = "✓ Enabled" if ver.get("Status") == "Enabled" else "✗ Disabled"

            log = s3.get_bucket_logging(Bucket=name)
            log_status = "✓ Enabled" if "LoggingEnabled" in log else "✗ Disabled"

            acl = s3.get_bucket_acl(Bucket=name)
            public = any(
                g["Grantee"].get("URI") in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ]
                for g in acl.get("Grants", [])
            )
            acl_status = "Public" if public else "Private"

            results.append({
                "BucketName": name,
                "Encryption": enc,
                "Versioning": ver_status,
                "Logging": log_status,
                "ACL": acl_status,
                "Public Access": "✓" if public else "✗",
            })

        os.makedirs("reports", exist_ok=True)
        filename = f"Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join("reports", filename)

        # Normalize symbols before saving (avoid Unicode)
        for r in results:
            for k, v in r.items():
                if isinstance(v, str):
                    r[k] = v.replace("✓", "Enabled").replace("✗", "Disabled")

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

        # Return response after closing the file
        return jsonify({
            "total_buckets": len(results),
            "compliant": sum(
                1 for r in results
                if r["Encryption"] == "Enabled" and r["Versioning"] == "Enabled"
            ),
            "filename": filename
        })


    except Exception as e:
        print("AWS connection error:", e)
        return jsonify({"error": str(e)}), 500


# === START SERVER ===
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
