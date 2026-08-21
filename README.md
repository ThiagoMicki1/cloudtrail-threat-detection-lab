# CloudTrail Threat Detection Lab

A Python-based blue-team lab that analyzes sanitized AWS CloudTrail JSON logs, applies detection rules, maps alerts to MITRE ATT&CK techniques, prints terminal findings, and optionally exports a JSON report.

This project is safe for a public GitHub portfolio. It does not connect to AWS, does not use AWS credentials, and does not include real logs, real account IDs, real ARNs, real IPs, or private data.

## Why I Built This

Cloud security roles expect defenders to understand cloud audit logs, identity activity, suspicious API behavior, and detection logic. This lab shows how to turn CloudTrail events into explainable alerts with evidence and recommendations.

## Skills Demonstrated

- Python automation with the standard library
- AWS CloudTrail JSON parsing
- Detection engineering fundamentals
- IAM and AWS account security monitoring
- MITRE ATT&CK mapping
- Security report generation
- Unit testing
- Public-safe sample data handling

## Why CloudTrail Matters

CloudTrail records AWS account activity such as console logins, IAM changes, STS role assumptions, S3 policy updates, and CloudTrail configuration changes. For defenders, these events are a key source for investigating suspicious identity behavior, privilege changes, audit-log tampering, and exposed cloud resources.

## How the Detection Engine Works

1. Reads one CloudTrail JSON file or every `.json` file in a folder.
2. Accepts CloudTrail-style `Records` arrays, JSON lists, or single JSON objects.
3. Runs event-based detection rules.
4. Runs a simple threshold rule for repeated `AccessDenied` or `UnauthorizedOperation` events.
5. Prints terminal alerts with severity, evidence, MITRE mapping, and recommendations.
6. Optionally writes a JSON report.

## Detection Rules Summary

| Rule | Severity | Why It Matters |
| --- | --- | --- |
| Root account usage | CRITICAL | Root should rarely be used and should be protected with MFA. |
| Failed console login | WARN | Repeated failures can indicate brute force or password guessing. |
| AccessDenied spike | WARN | Permission probing can indicate discovery or stolen credentials. |
| New access key creation | HIGH | Access keys can provide long-lived programmatic access. |
| IAM policy attachment or policy change | HIGH | Permission changes can create privilege escalation paths. |
| Security group opened to `0.0.0.0/0` | HIGH | Public ingress can expose services to the internet. |
| CloudTrail stopped or deleted | CRITICAL | Disabling logs can hide attacker activity. |
| Suspicious `AssumeRole` activity | HIGH | Role assumption can be abused for privilege escalation or evasion. |
| Console login without MFA | HIGH | Valid credentials without MFA are easier to abuse. |
| IAM user created | WARN | New users can become persistence mechanisms. |
| MFA device deactivated | CRITICAL | MFA removal weakens account protection. |
| S3 public-risky bucket policy | CRITICAL | Public bucket permissions can lead to data exposure. |

## MITRE ATT&CK Mapping

Examples used in this lab:

- `T1078 Valid Accounts`
- `T1110 Brute Force`
- `T1098 Account Manipulation`
- `T1136.003 Create Account: Cloud Account`
- `T1556.006 Modify Authentication Process: Multi-Factor Authentication`
- `T1562 Impair Defenses`
- `T1619 Cloud Storage Object Discovery`

See [docs/mitre-attack-mapping.md](docs/mitre-attack-mapping.md) for the full mapping.

## Project Structure

```text
cloudtrail-threat-detection-lab/
|-- cloudtrail_detector/          # Python loader, rules, and CLI
|-- sample_logs/                  # Sanitized fake CloudTrail events
|-- tests/                        # Unit tests
|-- docs/                         # Detection and CloudTrail concepts
|-- reports/                      # Sample terminal and JSON reports
|-- README.md
|-- requirements.txt
|-- .gitignore
`-- .gitattributes
```

## Run the Detector

Analyze the sample log folder:

```bash
python -m cloudtrail_detector sample_logs
```

Analyze one file:

```bash
python -m cloudtrail_detector sample_logs/cloudtrail-sample-events.json
```

## Export JSON

```bash
python -m cloudtrail_detector sample_logs --json-out reports/local/alert-report.json
```

## Run Tests

```bash
python -m unittest discover -s tests
```

## Example Output

```text
========================================================================
CloudTrail Threat Detection Lab
========================================================================
Total alerts: 12
Severity counts: INFO: 0 | WARN: 3 | HIGH: 5 | CRITICAL: 4

------------------------------------------------------------------------
[CRITICAL] Root account usage
Time:        2026-08-20T12:00:00Z
Event:       ConsoleLogin
Actor:       arn:aws:iam::123456789012:root
Source IP:   203.0.113.10
Region:      us-east-1
MITRE:       T1078 Valid Accounts - Initial Access / Privilege Escalation
Evidence:    CloudTrail event was performed by the AWS root identity.
Recommend:   Avoid root account activity. Use named IAM roles/users with MFA and least privilege.
```

Full examples:

- [reports/sample-terminal-output.txt](reports/sample-terminal-output.txt)
- [reports/sample-alert-report.json](reports/sample-alert-report.json)

## Scope and Safety Notes

- Uses sanitized fake CloudTrail events only.
- Uses fake sample AWS account ID `123456789012`.
- Uses documentation-only IP ranges: `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- Does not use boto3.
- Does not connect to AWS.
- Does not request or store AWS credentials.
- Does not deploy or modify cloud resources.

## What I Learned

- CloudTrail events can be converted into practical detections with simple Python.
- Detection rules are stronger when they include evidence and recommendations.
- MITRE ATT&CK mapping helps explain the attacker behavior behind an alert.
- Safe sample data makes a cloud security project public-portfolio friendly.

## Future Improvements

- Add CSV export
- Add severity filtering
- Add configurable thresholds
- Add Sigma-style rule files
- Add CloudTrail Lake query examples as documentation only
- Add GitHub Actions test workflow
- Add more S3, KMS, GuardDuty, and CloudTrail management detections

## Commands to Publish

```bash
cd "/mnt/c/Users/Thiago Micki/PersonalProjects/cloudtrail-threat-detection-lab"

python -m unittest discover -s tests
python -m cloudtrail_detector sample_logs
python -m cloudtrail_detector sample_logs --json-out reports/local/alert-report.json

git init -b main
git add .
git commit -m "Add CloudTrail threat detection lab"

gh repo create cloudtrail-threat-detection-lab \
  --public \
  --description "Python lab for detecting suspicious AWS CloudTrail activity using sanitized sample logs, MITRE ATT&CK mapping, and JSON reports." \
  --source . \
  --remote origin \
  --push
```
