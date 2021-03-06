import os
import sys
import boto3
import argparse
import multiprocessing

class User_With_Access():
    #A user who has access
    username = ""
    read_access = False
    write_access = False
    actions = []
    groups = []
    def __init__(self, un):
        username = un
def exit():
    os.system('cls' if os.name == 'nt' else 'clear')
    sys.exit(0)

def user_details_screen(target_arn, resource_type, roles_list, user_list, user_number):
    os.system('cls' if os.name == 'nt' else 'clear')
    #print user_number
    #print("{}".format(user_list[user_number-1].username))
    user = user_list[user_number-1]

    print ("{} has access to this resource.".format(user.username))
    print ("\tThe following groups provide the user with access to this resource:")
    for g in user.groups:
        print("\t\t{}".format(g))
    print("\tThis user can perform the following actions:")
    for a in user.actions:
        print("\t\t{}".format(a))

    print("\n[1] Go back.")
    print("[2] Exit.\n\n")

    action = input(">>> ")
    if action == '1':
        users_screen(target_arn, resource_type, roles_list, user_list)
    if action == '2':
        exit()
    else:
        services_screen(target_arn, resource_type, roles_list, user_list)


def users_screen(target_arn, resource_type, roles_list, user_list):
    os.system('cls' if os.name == 'nt' else 'clear')
    print ("Users with access to {}\n".format(target_arn))
    i = 1
    for user in user_list:
        print ("[{}] {}".format(i, user.username))
        i += 1
    print("\n[{}] Go back.".format(i))
    print("[{}] Exit.\n\n".format(i+1))

    action = input(">>> ")
    try:
        number = int(action)
    except:
        users_screen(target_arn, resource_type, roles_list, user_list)
    if int(action) < i and int(action) > 0:
        user_details_screen(target_arn, resource_type, roles_list, user_list, int(action))
    if int(action) == i:
        access_screen(target_arn, resource_type, roles_list, user_list)
    if int(action) == i+1:
        exit()
    else:
        users_screen(target_arn, resource_type, roles_list, user_list)

def services_screen(target_arn, resource_type, roles_list, user_list):
    os.system('cls' if os.name == 'nt' else 'clear')
    print ("Services with access to {}\n".format(target_arn))
    for r in roles_list:
        print ("{} has access to read or write the given ARN.".format(r))
    print("\n[1] Go back.")
    print("[2] Exit.\n\n")

    action = input(">>> ")
    if action == '1':
        access_screen(target_arn, resource_type, roles_list, user_list)
    if action == '2':
        exit()
    else:
        services_screen(target_arn, resource_type, roles_list, user_list)


def access_screen(target_arn, resource_type, roles_list, user_list):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("AWS N0-SC" + u'\u2295' + "P3 results for the {} object with ARN {}\n".format(resource_type,target_arn))
    print("See below for list of services and users for access.\n")
    print("[1] List of services with access.")
    print("[2] List of users with access.")
    print("[3] Exit.\n\n")
    action = input(">>> ")
    if action == '1':
        services_screen(target_arn, resource_type, roles_list, user_list)
    if action == '2':
        users_screen(target_arn, resource_type, roles_list, user_list)
    if action == '3':
        exit()
    else:
        access_screen(target_arn, resource_type, roles_list, user_list)
def determine_actions(action, current_user, resource_type):
    #print resource_type
    if type(action) == list:
        for a in action:
            if resource_type in a:
                current_user.actions.append(a)
    else:
        if resource_type in action:
            current_user.actions.append(action)
def process_policy(resource, target_arn, current_status):
    if type(resource) == list:
        for r in resource:
            #print r
            if r == '*':
                return True
            r = r.split('*')[0]
            if r in target_arn:
                #print r
                return True
    else:
        #print resource
        if resource == '*':
            return True
        resource = resource.split('*')[0]
        if resource in target_arn:
            return True
        else:
            return False
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    #Set up ARGS
    parser = argparse.ArgumentParser()
    parser.add_argument("--arn", type=str, help="the resource to be located")
    #parser.add_argument("--type", type=str, help="the type of resource")
    parser.add_argument("--profile", type=str, help="profile which contains the resource")

    args = parser.parse_args()
    target_arn = args.arn
    resource_type = target_arn.split(':')[2]

    #Set up Boto3
    boto3.setup_default_session(profile_name='{}'.format(args.profile))
    iam = boto3.client('iam')

    #CREATE AN EMPTY LIST OF USERS WITH ACCESS TO THE RESOURCE
    users_with_access = []
    roles_with_access = {}

    role_list = []
    principals = []
    #Prep the assessment by gathering all roles
    sys.stdout.write("Assessing Role Policies")
    sys.stdout.flush()
    for role in iam.list_roles()['Roles']:

        for statement in role['AssumeRolePolicyDocument']['Statement']:
            if statement['Action'] == 'sts:AssumeRole' and statement['Effect'] == 'Allow':
                if 'Service' in  statement['Principal']:
                    principal = statement['Principal']['Service']
                if 'AWS' in statement['Principal']:
                    principal = statement['Principal']['AWS']
                if len(principal) < 5:
                    for p in principal:
                        if p not in principals:
                            principals.append(p)
                else:
                    if principal not in principals:
                        #SHOULD NOT APPEND HERE, SHOULD APPEND BELOW
                        #DEPENDING ON EFFECT
                        principals.append(principal)
        role_name = role['RoleName']
        role_arn = role['Arn']
        role_object = [role_name, role_arn]
        role_list.append(role_object)

        for policy in iam.list_role_policies(RoleName=role_name)['PolicyNames']:
            for p in iam.get_role_policy(RoleName=role_name, PolicyName=policy)['PolicyDocument']['Statement']:
                role_does_have_access = False
                sys.stdout.write('.')
                sys.stdout.flush()
                try:
                    temporary_results = process_policy(p['Resource'], target_arn, role_does_have_access)
                    if temporary_results == True:
                        role_does_have_access = True
                    if role_does_have_access:
                        roles_with_access[role_name] = p['Action']
                except:
                    pass
    sys.stdout.write('\n')
    sys.stdout.write('\n')

    #Generate the user list
    user_list = iam.list_users()
    access_via_attached_policy = False
    access_via_group_policy = []
    access_via_attached_group_policy = []

    sys.stdout.write("Assessing User & Group Policies")
    sys.stdout.flush()
    for user in user_list['Users']:
        #print "Checking user {}".format(user)
        un = user['UserName']
        current_user = User_With_Access(un)
        current_user.username = un
        current_user.actions = []
        current_user.groups = []
        #print un
        user_does_have_access = False
        for user_policy in (iam.list_user_policies(UserName=un))['PolicyNames']:
            #Code repeats below (condense this)
            sys.stdout.write('.')
            sys.stdout.flush()
            policy_details = (iam.get_user_policy(UserName=un, PolicyName=user_policy))['PolicyDocument']['Statement']
            for policy in policy_details:
                try:
                    new_action = policy['Action']
                    resource = policy['Resource']
                    effect = policy['Effect']
                    temporary_results = process_policy(resource, target_arn, user_does_have_access)
                    if temporary_results == True and effect == "Allow":
                        user_does_have_access = True
                        determine_actions(new_action, current_user, resource_type)
                        if "Get" in new_action:
                            current_user.read_access = True
                        if "Put" in new_action:
                            current_user.write_access = True
                        access_via_attached_policy = True
                except Exception as e:
                    print (e)

        for user_policy in (iam.list_attached_user_policies(UserName=un))['AttachedPolicies']:

            user_policy = user_policy['PolicyArn']
            #Code repeats below (condense this)
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                policy_details = (iam.get_policy_version(PolicyArn=user_policy,VersionId='v1'))['PolicyVersion']['Document']['Statement']
            except Exception as e:
                print(e)
                break
            for policy in policy_details:
                try:
                    new_action = policy['Action']
                except Exception as e:
                    break
                resource = policy['Resource']
                effect = policy['Effect']
                temporary_results = process_policy(resource, target_arn, user_does_have_access)
                if temporary_results == True and effect == "Allow":
                    user_does_have_access = True
                    determine_actions(new_action, current_user, resource_type)
                    if "Get" in new_action:
                        current_user.read_access = True
                    if "Put" in new_action:
                        current_user.write_access = True
                    access_via_attached_policy = True
        user_groups = iam.list_groups_for_user(UserName='{}'.format(un))
        for group in user_groups['Groups']:
            sys.stdout.write('.')
            sys.stdout.flush()
            g = group['GroupName']
            print(g)
            for group_policy in iam.list_group_policies(GroupName=g)['PolicyNames']:
                policy_details = (iam.get_group_policy(GroupName=g, PolicyName=group_policy))['PolicyDocument']['Statement']
                for policy in policy_details:
                    try:
                        new_action = policy['Action']
                    except Exception as e:
                        break
                    resource = policy['Resource']
                    effect = policy['Effect']
                    temporary_results = process_policy(resource, target_arn, user_does_have_access)
                    if temporary_results == True and effect == "Allow":
                        user_does_have_access = True
                        determine_actions(new_action, current_user, resource_type)
                        if "Get" in new_action:
                            current_user.read_access = True
                        if "Put" in new_action:
                            current_user.write_access = True
                        if g not in current_user.groups:
                            current_user.groups.append(g)
            for attached_policy in iam.list_attached_group_policies(GroupName=g)['AttachedPolicies']:
                try:
                    policy_versions = iam.get_policy_version(PolicyArn=attached_policy['PolicyArn'], VersionId='v1')
                except:
                    pass
                try:
                    policy_versions = iam.get_policy_version(PolicyArn=attached_policy['PolicyArn'], VersionId='v2')
                except:
                    pass
                try:
                    policy_versions = iam.get_policy_version(PolicyArn=attached_policy['PolicyArn'], VersionId='v3')
                except:
                    pass
                for policy in policy_versions['PolicyVersion']['Document']['Statement']:
                    try:
                        new_action = policy['Action']
                    except Exception as e:
                        break
                    resource = policy['Resource']
                    effect = policy['Effect']
                    temporary_results = process_policy(resource, target_arn, user_does_have_access)
                    if temporary_results == True:
                        user_does_have_access = True
                        determine_actions(new_action, current_user, resource_type)
                        if "Get" in new_action:
                            current_user.read_access = True
                        if "Put" in new_action:
                            current_user.write_access = True
                        if g not in current_user.groups:
                            current_user.groups.append(g)

        if user_does_have_access:

            if len(current_user.actions) > 0:
                users_with_access.append(current_user)

    access_screen(target_arn, resource_type, principals, users_with_access)

if __name__ == "__main__":
    main()
