☁️ CloudLock — Automated AWS S3 Auditing Service

CloudLock is a full-stack web application that automates SOC 2, ISO 27001, and HIPAA-style compliance checks across AWS S3 buckets.
It connects securely to your AWS account (via IAM Role ARN or JSON uploads), runs detailed policy + ACL audits, and exports a clean CSV report identifying security misconfigurations, public access, missing encryption, and more — all within seconds.

⚙️ Live Demo: Upload your JSON or connect your AWS account → Front-End Dashboard (index.html)

🎥 Features a glowing particle banner, animated video background, and interactive upload UI built with Flask + HTML/CSS + JS.

🔍 FEATURES
Automated S3 Auditing

Detects publicly accessible buckets via get_bucket_acl

Checks encryption status, versioning, and logging configuration

Flags MFA Delete, cross-account access, and missing lifecycle policies

Data Export

Generates downloadable .csv audit reports like:
soc2_s3_audit_report_<timestamp>.csv

Summary metrics: Total Buckets | Compliant | Non-Compliant | High-Risk Findings

Web Leak Detection (Optional)

Integrates a web scraper that scans for leaked bucket names or AWS keys across public domains (via WebLeakDetector).

Real-Time Dashboard

Modern front-end (see index.html and atom-one-dark.min.css)

Step-by-step upload UI:

Upload your JSON/CSV file

Wait for analysis

View compliance results

Download the report

Optionally connect your AWS account via the “🔗 Connect AWS Account” button.

🧠 HOW IT WORKS

Frontend Upload

Users upload a JSON file (from AWS CLI or exported list) or click Connect AWS Account.

Flask Backend

Receives the file through /upload

Uses Boto3 to run ACL, encryption, logging, and versioning checks

Audit Logic

Each bucket is evaluated for compliance risk

Metrics are stored in memory and written to CSV

Export & Visualization

CSV report saved under /reports

Results displayed in the UI via AJAX

BY ME AND RICK YANG!!

