# Detection Rules

Each rule returns an alert with severity, event name, actor, source IP, region, timestamp, evidence, MITRE ATT&CK mapping, and recommendation.

## Root Account Usage

Detects `userIdentity.type = Root`.

Security meaning: root account activity is high risk because root has full account authority.

Recommendation: avoid root usage, enable MFA, and use least-privilege IAM roles.

## Failed Console Login

Detects `ConsoleLogin` events where `responseElements.ConsoleLogin = Failure`.

Security meaning: failed console logins may indicate password guessing or brute force attempts.

Recommendation: review source IPs, enforce MFA, and investigate repeated failures.

## AccessDenied Spike

Detects three or more `AccessDenied` or `UnauthorizedOperation` events from the same actor and source IP.

Security meaning: repeated denials can indicate permission probing, stale credentials, or attempted misuse.

Recommendation: review the actor, source IP, attempted APIs, and recent authentication history.

## New Access Key Creation

Detects `CreateAccessKey`.

Security meaning: access keys can provide long-lived programmatic access.

Recommendation: verify the key was approved, rotate unexpected keys, and remove unused keys.

## IAM Policy Attachment or Policy Change

Detects policy events such as `AttachRolePolicy`, `PutUserPolicy`, `CreatePolicyVersion`, and `SetDefaultPolicyVersion`.

Security meaning: policy changes can increase privilege or create persistence.

Recommendation: review policy diffs and confirm the change was approved.

## Security Group Opened to the World

Detects `AuthorizeSecurityGroupIngress` with `0.0.0.0/0` or `::/0`.

Security meaning: public ingress can expose services to internet scanning and exploitation.

Recommendation: restrict inbound access to known trusted ranges.

## CloudTrail Stopped or Deleted

Detects `StopLogging` and `DeleteTrail`.

Security meaning: stopping audit logs can hide attacker activity.

Recommendation: re-enable logging and investigate the actor immediately.

## Suspicious AssumeRole Activity

Detects `AssumeRole` from suspicious documentation IPs in the sample data or role names containing admin-like terms.

Security meaning: role assumption can be used for privilege escalation, lateral movement, or defense evasion.

Recommendation: validate source IP, role target, session name, and business reason.

## Console Login Without MFA

Detects successful `ConsoleLogin` where `additionalEventData.MFAUsed = No`.

Security meaning: valid credentials without MFA are easier to abuse.

Recommendation: require MFA for console users.

## IAM User Created

Detects `CreateUser`.

Security meaning: new IAM users can be used for persistence.

Recommendation: verify approval and prefer federated access.

## MFA Device Deactivated

Detects `DeactivateMFADevice` and `DeleteVirtualMFADevice`.

Security meaning: MFA removal weakens identity protection.

Recommendation: confirm the change, re-enable MFA, and review recent activity.

## S3 Public-Risky Bucket Policy

Detects `PutBucketPolicy` statements with `Effect = Allow`, public principal, and risky S3 actions.

Security meaning: public bucket policies can expose sensitive cloud data.

Recommendation: remove public principals and enable S3 Block Public Access.
