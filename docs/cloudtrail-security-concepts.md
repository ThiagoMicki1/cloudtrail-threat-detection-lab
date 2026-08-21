# CloudTrail Security Concepts

## What CloudTrail Records

CloudTrail records AWS account activity, including actions taken through the AWS Console, AWS APIs, SDKs, CLI, and AWS services. A CloudTrail event usually includes:

- Event time
- Event name
- AWS service
- User identity
- Source IP
- AWS region
- Request parameters
- Response elements
- Error codes or messages

## Why Defenders Care

CloudTrail helps answer core investigation questions:

- Who performed the action?
- What API was called?
- Where did the request come from?
- When did it happen?
- Did it succeed or fail?
- What resource or permission was changed?

## Common Cloud Security Signals

- Root account usage
- IAM user or access key creation
- Policy changes
- Failed console logins
- MFA removal
- Public network exposure
- S3 bucket policy changes
- CloudTrail logging changes
- STS role assumption

## Scope of This Lab

This lab uses sanitized sample CloudTrail JSON only. It does not connect to AWS and does not use real CloudTrail logs.

The goal is to practice detection logic and reporting without handling sensitive data.

## References

- AWS CloudTrail User Guide: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
- Understanding CloudTrail events: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html
