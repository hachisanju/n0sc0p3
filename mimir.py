import os
import sys
import boto3
import argparse
import multiprocessing

class EC2_Instance():
    #something
    print "Nothing"

def ec2(profile):
    os.system('cls' if os.name == 'nt' else 'clear')
    print "Arrived"

def menu(profile):
    os.system('cls' if os.name == 'nt' else 'clear')
    boto3.setup_default_session(profile_name='{}'.format(profile))
    print("\"The name's Mimir; Smartest man alive!\"\n")
    print("Select the service you want to retrieve an ARN for:\n")
    print("[1] EC2.")
    print("[2] DynamoDB.")
    print("[3] Exit.\n\n")
    action = raw_input(">>> ")
    if action == '1':
        ec2(profile)
        #services_screen(target_arn, resource_type, roles_list, user_list)
    if action == '2':
        sys.exit(0)
        #users_screen(target_arn, resource_type, roles_list, user_list)
    if action == '3':
        sys.exit(0)
    else:
        #access_screen(target_arn, resource_type, roles_list, user_list)
        sys.exit(0)

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    #Set up ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=str, help="profile which contains the resource")
    args = parser.parse_args()
    menu(args.profile)

if __name__ == "__main__":
    main()
