#!/usr/bin/env python3

import argparse
import boto3
from botocore.exceptions import ClientError


def list_users(profile_name=None):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam')
    
    try:
        response = iam_client.list_users()
        print("Users:")
        return [user['UserName'] for user in response['Users']]          
    except ClientError as error:
        code = error.response['Error']['Code']
        print('FAILURE: ')
        if code == 'UnauthorizedOperation':
            print(' Problem logging')
        else:
            print(' ' + code)


def list_roles(profile_name=None):
    session = boto3.Session(profile_name=profile_name)
    iam_client = session.client('iam')
    try:
        response = iam_client.list_roles()
        print("Roles:")
        return [role['RoleName'] for role in response['Roles']]
    except ClientError as error:
        code = error.response['Error']['Code']
        print('FAILURE: ')
        if code == 'UnauthorizedOperation':
            print(' Problem logging')
        else:
            print(' ' + code)

def start_policy_generation(profile_name, entity_name, account_id, cloudtrail):
    try:
        regions = [
            'eu-north-1', 'ap-south-1', 'eu-west-3', 'eu-west-2',
            'eu-west-1', 'ap-northeast-3', 'ap-northeast-2'
            'ap-northeast-1', 'sa-east-1', 'ca-central-1', 
            'ap-southeast-2', 'eu-central-1', 'us-east-1', 'us-east-2',
            'us-west-1', 'us-west-2']
        for r in regions:
            session = boto3.Session(profile_name=profile_name)
            analyzer_client = session.client('accessanalyzer', region_name=r)
            response = analyzer_client.start_policy_generation(
                policyGenerationDetails={
                    'principalArn': f"arn:aws:iam::{account_id}:{entity_name}"
                },
                cloudTrailDetails={
                    'trails': [
                        {
                            'cloudTrailArn': 'string',
                            'regions': [
                                'string',
                            ],
                            'allRegions': True|False
                        },
                    ],
                    'accessRole': 'string',
                    'startTime': datetime(2015, 1, 1),    
                    'endTime': datetime(2015, 1, 1)                       
                }         
            )
            return response['jobId']
    except Exception as e:
        print(f"Error occurred while starting policy generation: {e}")
        return None

def get_generated_policy(profile_name, job_id):
    try:
        regions = [
            'eu-north-1', 'ap-south-1', 'eu-west-3', 'eu-west-2',
            'eu-west-1', 'ap-northeast-3', 'ap-northeast-2'
            'ap-northeast-1', 'sa-east-1', 'ca-central-1', 
            'ap-southeast-2', 'eu-central-1', 'us-east-1', 'us-east-2',
            'us-west-1', 'us-west-2']
        for r in regions:
            session = boto3.Session(profile_name=profile_name)
            analyzer_client = session.client('accessanalyzer', region_name=r)
            while True:
                response = analyzer_client.get_generated_policy(jobId=job_id)
                status = response['status']
                if status == 'COMPLETE':
                    return response['policy']
                elif status == 'FAILED':
                    print(f"Policy generation failed for job ID {job_id}")
                    return None
                else:
                    print(f"Policy generation in progress for job ID {job_id}, status: {status}. Waiting...")
                    time.sleep(5)
    except Exception as e:
        print(f"Error occurred while getting generated policy: {e}")
        return None

def store_in_database(data):
    connection = mysql.connector.connect(
        host='your_mysql_host',
        user='your_mysql_user',
        password='your_mysql_password',
        database='your_mysql_database'
    )

    cursor = connection.cursor()

    for entity_name, analysis_result in data.items():
        cursor.execute("INSERT INTO iam_analysis (entity_name, analysis_result) VALUES (%s, %s)", (entity_name, analysis_result))

    connection.commit()
    cursor.close()
    connection.close()

def getaccountid(profile_name=None):
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client('sts')
    
    try:
        return sts_client.get_caller_identity()["Account"]       
    except ClientError as error:
        code = error.response['Error']['Code']
        print('FAILURE: ')
        if code == 'UnauthorizedOperation':
            print(' Problem logging')
        else:
            print(' ' + code)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS IAM list users and roles")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--cloudtrail", help="AWS CloudTrail ARN from where to generate AWS IAM policies")
    args = parser.parse_args()

    profile_name = args.profile if args.profile else None
    cloudtrail_arn = args.cloudtrail if args.cloudtrail else None

    print(f"Using AWS profile: {profile_name}")

    print("Calling GetAccountID and List Functions!---------------")
    acct_id = getaccountid(profile_name)
    users = list_users(profile_name)
    roles = list_roles(profile_name)

    print("Got Data!------------------")
    print('Users: [%s]' % ', '.join(map(str, users)))
    print('Roles: [%s]' % ', '.join(map(str, roles)))


    analysis_data = {}

    print("Analyzing!-------------------------------")
    for user in users:
        job_id = start_policy_generation(profile_name, f"user/{user}", acct_id, cloudtrail_arn)
        if job_id:
            policy = get_generated_policy(profile_name, job_id)
            if policy:
                print(f"IAM Policy generated for user {user}:")
                print(policy)
                print()

    for role in roles:
        job_id = start_policy_generation(profile_name, f"role/{role}")
        if job_id:
            policy = get_generated_policy(profile_name, job_id)
            if policy:
                print(f"IAM Policy generated for role {role}:")
                print(policy)
                print()

    print(analysis_data)
