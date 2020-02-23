import unittest
import json
from parliament.cli import analyze_authorization_file


class TestAuthDetailsFile(unittest.TestCase):
    def test_auth_details_example(self):
        auth_details_json = {
          "UserDetailList": [
            {
              "Path": "/",
              "UserName": "obama",
              "UserId": "YAAAAASSQUEEEN",
              "Arn": "arn:aws:iam::012345678901:user/obama",
              "CreateDate": "2019-12-18 19:10:08+00:00",
              "GroupList": [
                "admin"
              ],
              "AttachedManagedPolicies": [],
              "Tags": []
            }
          ],
          "GroupDetailList": [
            {
              "Path": "/",
              "GroupName": "admin",
              "GroupId": "YAAAAASSQUEEEN",
              "Arn": "arn:aws:iam::012345678901:group/admin",
              "CreateDate": "2017-05-15 17:33:36+00:00",
              "GroupPolicyList": [],
              "AttachedManagedPolicies": [
                {
                  "PolicyName": "AdministratorAccess",
                  "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
                }
              ]
            }
          ],
          "RoleDetailList": [
            {
              "Path": "/",
              "RoleName": "MyRole",
              "RoleId": "YAAAAASSQUEEEN",
              "Arn": "arn:aws:iam::012345678901:role/MyRole",
              "CreateDate": "2019-08-16 17:27:59+00:00",
              "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                  {
                    "Effect": "Allow",
                    "Principal": {
                      "Service": "ssm.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                  }
                ]
              },
              "InstanceProfileList": [],
              "RolePolicyList": [
                {
                  "PolicyName": "Stuff",
                  "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Action": [
                                    "s3:ListBucket",
                                    "s3:Put*",
                                    "s3:Get*",
                                    "s3:*MultipartUpload*"
                                ],
                                "Resource": [
                                    "*"
                                ],
                                "Effect": "Allow"
                            }
                        ]
                  }
                }
              ],
              "AttachedManagedPolicies": [],
              "Tags": [],
              "RoleLastUsed": {}
            },
              {
              "Path": "/",
              "RoleName": "MyOtherRole",
              "RoleId": "YAAAAASSQUEEEN",
              "Arn": "arn:aws:iam::012345678901:role/MyOtherRole",
              "CreateDate": "2019-08-16 17:27:59+00:00",
              "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                  {
                    "Effect": "Allow",
                    "Principal": {
                      "Service": "ssm.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                  }
                ]
              },
              "InstanceProfileList": [],
              "RolePolicyList": [
                {
                  "PolicyName": "SupYo",
                  "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                      {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": [
                          "s3:PutBucketPolicy",
                          "s3:PutBucketAcl",
                          "s3:PutLifecycleConfiguration",
                          "s3:PutObject",
                          "s3:GetObject",
                          "s3:DeleteObject",
                        ],
                        "Resource": "*"
                      }
                    ]
                  }
                }
              ],
              "AttachedManagedPolicies": [],
              "Tags": [],
              "RoleLastUsed": {}
            }
          ],
          "Policies": [
            {
              "PolicyName": "NotYourPolicy",
              "PolicyId": "YAAAAASSQUEEEN",
              "Arn": "arn:aws:iam::012345678901:policy/NotYourPolicy",
              "Path": "/",
              "DefaultVersionId": "v9",
              "AttachmentCount": 1,
              "PermissionsBoundaryUsageCount": 0,
              "IsAttachable": True,
              "CreateDate": "2020-01-29 21:24:20+00:00",
              "UpdateDate": "2020-01-29 23:23:12+00:00",
              "PolicyVersionList": [
                {
                  "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                      {
                        "Sid": "VisualEditor0",
                        "Effect": "Allow",
                        "Action": [
                          "s3:PutBucketPolicy",
                          "s3:PutBucketAcl",
                          "s3:PutLifecycleConfiguration",
                          "s3:PutObject",
                          "s3:GetObject",
                          "s3:DeleteObject",
                        ],
                        "Resource": [
                          "arn:aws:s3:::mybucket/*",
                          "arn:aws:s3:::mybucket"
                        ]
                      }
                    ]
                  },
                  "VersionId": "v9",
                  "IsDefaultVersion": True,
                  "CreateDate": "2020-01-29 23:23:12+00:00"
                }
              ]
            }
          ]
        }
        findings = analyze_authorization_file(auth_details_json, None, False)

        expected_findings = "[RESOURCE_POLICY_PRIVILEGE_ESCALATION - Possible resource policy privilege escalation on * due to s3:DeleteObject not being allowed, but does allow s3:PutBucketPolicy - {'filepath': 'arn:aws:iam::012345678901:role/MyRole'}, RESOURCE_POLICY_PRIVILEGE_ESCALATION - Possible resource policy privilege escalation on * due to s3:DeleteObject not being allowed, but does allow s3:PutBucketAcl - {'filepath': 'arn:aws:iam::012345678901:role/MyRole'}, RESOURCE_POLICY_PRIVILEGE_ESCALATION - Possible resource policy privilege escalation on * due to s3:DeleteObject not being allowed, but does allow s3:PutLifecycleConfiguration - {'filepath': 'arn:aws:iam::012345678901:role/MyRole'}]"
        self.maxDiff = None
        self.assertEqual(str(findings), expected_findings)
