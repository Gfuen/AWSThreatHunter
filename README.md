# AWSThreatHunter

The follow is a Python Project meant for AWS environments where users will input AWS profile, account id, and cloudtrail arn to use
and it will generate AWS IAM policies for the AWS IAM principals within the account. Please note that the CloudTrail arn provided
must have already been generating CloudTrail logs because this projects utilizes AWS IAM Access analyzer to generate the
AWS IAM policies.

Then, from there the AWS IAM policies will be uploaded either to Splunk/Elastic in order to queried for specific AWS IAM users or roles
and then Splunk/Elastic queries will also be generated to help with detection against privileged actions that might need looking into
according to https://github.com/primeharbor/sensitive_iam_actions/tree/main/policies.

NOTE---STILL BEING WORKED ON
