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

def analyze_access(profile_name, entity_name):
    session = boto3.Session(profile_name=profile_name)
    analyzer_client = session.client('accessanalyzer', region_name='us-east-2')
    try:
        response = analyzer_client.get_analyzed_resource(
            analyzerArn='arn:aws:access-analyzer:region:account-id:analyzer/access-analyzer-name',
            resourceArn=entity_name
        )
        return response['analyzedResource']
    except ClientError as error:
        code = error.response['Error']['Code']
        print('FAILURE: ')
        if code == 'UnauthorizedOperation':
            print(' Problem logging')
        else:
            print(' ' + code)

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
    args = parser.parse_args()

    profile_name = args.profile if args.profile else None

    print(f"Using AWS profile: {profile_name}")

    account_id = getaccountid(profile_name)
    users = list_users(profile_name)
    roles = list_roles(profile_name)

    analysis_data = {}

    for user in users:
        analysis_data[user] = analyze_access(profile_name, f"arn:aws:iam::account-id:user/{user}")

    for role in roles:
        analysis_data[role] = analyze_access(profile_name, f"arn:aws:iam::account-id:role/{role}")

    print(analysis_data)
