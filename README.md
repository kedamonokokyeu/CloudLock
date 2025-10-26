                  ---------- ☁️ CloudLock ----------

At UC Berkeley, there are over 1,650 startups, and over 1,800 founders. From BioLabs, Free Ventures, to Skydeck, there are countless startups reaching for the stars. But while large enterprises can afford premium composit suites, many of the smaller teams in these accelerators lack visibility into how their cloud data is stored. In order to present something with practical revelance in the environment, we built CloudLock --- startups deserve a simple and transparent way to understand their cloud security posture.

                      What is it? And why is it different?

CloudLock is an automatic auditing system designed for security and checking compliance regulations in accordance with the Logical and Physical Access Controls (CC6.1) from SOC2 compliance. It maintains an IAM role that can be connected to a user's AWS account and checks without bypassing privacy SOC2 regulations.
These regulations include:
- Encryption
- Access Control
- Logging Configuration
- Versioning

But with tight budgets, companies cannot always log every S3 Bucket available in their AWS storage, nor can they ensure that all data is protected by the highest encryption levels provided by AWS.
Therefore, we provided a valuation metric that quantifies risk. Given the tags of SOC3 buckets, the auditor can use this risk valuation to provide a recommendation on whether these buckets should be logged or not by comparing the information of the bucket relatively to its encryption level.
We have also implemented the first phase for our web-scraping ideas for the auditor that automatically web-scrapes for potential data leaks throughout GitHub and Reddit, cross-referencing bucket names and metadata to flag external sources.

                            📝 How We Built It

Auditing Core

- boto3 - AWS SDK for listing buckets, fetching ACLs, and checking logging/encryption status
- botocore.exceptions - for error handling and cross-account sharing
- CSV - Data export that is readable and ready-to-go / also provides info on what needs to be changed

Risk Quantification

- Python (pandas, re) – Cleans and analyzes metadata, tags, and naming conventions
- Sensitivity Scoring – Computes a normalized metric (0–1) based on inferred data importance
- Risk Inference – Balances encryption strength vs. content sensitivity to identify high-risk zones

Leak Detection

- BeautifulSoup - webscraping library
- lxml - text parser

Backend API

- Flask + CORS - Provided REST endpoints for uploading JSON configurations or connecting AWS credentials
- Threaded Execeution to audit multiple buckets concurrently
- CSV report generator

                       ✈️ What's next for CloudLock?

We want to:

Further our WebScraping initiative --- In addition to flagging websites, forums, and threads of potential data leakages, it also could automatically update the owners of the bucket storages through Slack or email. Rather than being limited to only GitHub or certain Reddit threats, it can also find websites that could lead to potential breaches in priavcy, such as TruthFinder, etc.

We want to add a web-based dashboard either by integrating Reflex or Next.js to create a more visually appealing and interactive way to see how your data storage aligns with SOC 2 regulations.

We want to expand past SOC2 regulations and include compliance laws from ISO 27001 (international data movement regulation), HIPAA Compliance (for healthcare startups).

Rather than only being focused on security and compliance, we plan to add an LLM-Powered Audit Assistant for financial audits as well, providing and interpreting audit reports, similar to Propaya or LLM summarizing softwares. 

Create a data-driven inference engine for our Risk-Scoring logic.

                   📋 - Evaluator’s Guide to CloudLock

CloudLock isn’t just an audit tool — it’s an educational platform that bridges the gap between cloud infrastructure and cyber awareness.
We aim to expose ourselves to the same technologies driving modern startups — AWS, APIs, and intelligent risk modeling — while contributing meaningfully to cloud computing security.

- Sponsor/Technology Stack

- AWS S3 – Core auditing target

- Flask – Backend API and file export layer

- Together.ai – (future) integration for intelligent log analysis

- Reflex – Planned front-end integration platform

- Intel Developer Cloud – Accelerated parallel scans for massive datasets

Not all startups can afford top-tier security suites --- but that doesn’t mean they should be left exposed.
CloudLock turns auditing into insight, allowing teams to understand, measure, and improve their data security posture one bucket at a time.

