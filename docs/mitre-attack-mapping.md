# MITRE ATT&CK Mapping

This lab maps CloudTrail detections to common ATT&CK techniques. The mapping is educational and should be tuned for a real environment.

| Detection | MITRE ATT&CK Mapping | Why It Fits |
| --- | --- | --- |
| Root account usage | `T1078 Valid Accounts` | Root usage can indicate abuse of a valid high-privilege account. |
| Failed console login | `T1110 Brute Force` | Failed logins can represent password guessing or credential attacks. |
| AccessDenied spike | `T1087 Account Discovery` / `T1110 Brute Force` | Permission probing may support discovery or credential misuse. |
| New access key creation | `T1098 Account Manipulation` | Creating credentials can help maintain access. |
| IAM policy change | `T1098 Account Manipulation` | Changing permissions can preserve or elevate access. |
| Security group opened to world | `T1562 Impair Defenses` / Initial Access support | Public exposure can weaken network boundaries and support follow-on access. |
| CloudTrail stopped or deleted | `T1562 Impair Defenses` | Disabling audit logs can reduce defensive visibility. |
| Suspicious AssumeRole | `T1078 Valid Accounts` / `T1098 Account Manipulation` | Role assumption can abuse valid access or elevated permissions. |
| Console login without MFA | `T1078 Valid Accounts` | A valid login without MFA is easier to abuse if credentials are stolen. |
| IAM user created | `T1136.003 Create Account: Cloud Account` | New cloud accounts can be used for persistence. |
| MFA deactivated | `T1556.006 Modify Authentication Process: Multi-Factor Authentication` | Removing MFA changes authentication protections. |
| S3 public-risky policy | `T1619 Cloud Storage Object Discovery` | Public cloud storage permissions can support discovery and exfiltration risk. |

## References

- MITRE ATT&CK `T1078 Valid Accounts`: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK `T1110 Brute Force`: https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK `T1098 Account Manipulation`: https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK `T1136.003 Create Account: Cloud Account`: https://attack.mitre.org/techniques/T1136/003/
- MITRE ATT&CK `T1556.006 Multi-Factor Authentication`: https://attack.mitre.org/techniques/T1556/006/
- MITRE ATT&CK `T1562 Impair Defenses`: https://attack.mitre.org/techniques/T1562/
- MITRE ATT&CK `T1619 Cloud Storage Object Discovery`: https://attack.mitre.org/techniques/T1619/
