import contextlib
import csv
import os
import re
import shutil
import sys

if len(sys.argv) < 3:
    print(r"Usage:")
    print(r"python csv_to_yml.py [CIS FILE] [HOSTS FILE]")
    print(r"python csv_to_yml.py rhel_9_cis.csv hosts.csv")
    print(r"python csv_to_yml.py amazon_linux_2_cis.csv hosts.csv")
    print(r"Make sure your CIS file ends with '_cis.csv'")
    exit(0)

##################
#
# DO NOT TO EDIT
#
##################
alignment=' '
line_count = 0
divider_count = 52
mode = 0o777

##################
#
# GLOBAL VARIABLES
#
##################
platform_name = sys.argv[1].split('_cis.csv',1)[0]
cis_csv = platform_name + "_" + "cis.csv"
host_file = sys.argv[2]

parent_directory = os.path.expanduser('./')
assignment_directory = "ansible_cis/"
inventory_directory = "inventory/"
outputs_directory = "outputs/"
role = platform_name + "_" + "cis_audit"
roles_tasks_directory = 'roles/'+role+'/tasks/'
roles_files_directory = 'roles/'+role+'/files/'
files_outputs_directory = 'roles/'+role+'/files/' + outputs_directory

playbook_path = os.path.join(parent_directory, assignment_directory)
inventory_path = os.path.join(parent_directory, assignment_directory, inventory_directory)
roles_tasks_path = os.path.join(parent_directory, assignment_directory, roles_tasks_directory)
roles_files_path = os.path.join(parent_directory, assignment_directory, roles_files_directory)
roles_files_outputs_path = os.path.join(parent_directory, assignment_directory, files_outputs_directory)

##################
#
# FIELD NUMBERS
#
##################
section_field_no = 0
recommendation_field_no = 1
profile_field_no = 2
title_field_no = 3
assessment_status_field_no = 4
description_field_no = 5
rationale_field_no = 6
impact_field_no = 7
remediation_field_no = 8
audit_verified_field_no = 10
audit_expected_result_field_no = 11
remmediation_verified_field_no = 12
remmediation_audit_expected_result_field_no = 13

def zip_folder_with_shutil(source_folder, output_path):
   shutil.make_archive(output_path, 'zip', source_folder)

with contextlib.suppress(FileExistsError):
    os.makedirs(inventory_path, mode)
    os.makedirs(roles_files_path, mode)
    os.makedirs(roles_files_outputs_path, mode)
    os.makedirs(roles_tasks_path, mode)

cis_inventory_yml = open(inventory_path + 'inv_' + platform_name, 'w')
print('---', file = cis_inventory_yml)
print('\n', file = cis_inventory_yml)
print('all:', file = cis_inventory_yml)
print(alignment*2 + 'children:', file = cis_inventory_yml)
print(alignment*4 + platform_name + ':', file = cis_inventory_yml)
print(alignment*6 + 'hosts:', file = cis_inventory_yml)

with open(host_file,'r') as host_file:
    host_reader = csv.reader(host_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    host_list = list(host_reader)

    for i in range(len(host_list)):
        print(alignment*8 + host_list[i][0] + ':', file = cis_inventory_yml)

cis_task_yml = open(roles_tasks_path + 'main.yml', 'w')
print('---', file = cis_task_yml)
print('\n', file = cis_task_yml)

print(f'- name: AUDIT - CURL TO GET INSTANCE DETAILS', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'uri:', file = cis_task_yml)
print(alignment*4 + 'url: "http://169.254.169.254/latest/dynamic/instance-identity/document"', file = cis_task_yml)
print(alignment*4 + 'return_content: true', file = cis_task_yml)
print(alignment*2 + 'register: instance_details', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- upload_compliance_cloud', file = cis_task_yml)
print('\n', file = cis_task_yml)

print('\n', file = cis_task_yml)
print(f'- name: AUDIT - GET INSTANCE ID', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'shell: "cat /var/lib/amazon/ssm/registration | awk -F \\"\\\\\\"\\" \'{print $4}\'\"', file = cis_task_yml)
print(alignment*2 + 'register: instance_id', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- upload_compliance_hybrid', file = cis_task_yml)
print('\n', file = cis_task_yml)

print(f'- name: AUDIT - GET INSTANCE REGION', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'shell: "cat /var/lib/amazon/ssm/registration | awk -F \\"\\\\\\"\\" \'{print $8}\'\"', file = cis_task_yml)
print(alignment*2 + 'register: instance_region', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- upload_compliance_hybrid', file = cis_task_yml)
print('\n', file = cis_task_yml)

print(f'- name: AUDIT - SHOW INSTANCE DETAILS', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'debug:', file = cis_task_yml)
print(alignment*4 + 'msg: "{{ instance_id.stdout_lines[0] | default(instance_details.json.instanceId) }} - {{ instance_region.stdout_lines[0] | default(instance_details.json.region) }}"', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- upload_compliance_cloud', file = cis_task_yml)
print(alignment*4 + '- upload_compliance_hybrid', file = cis_task_yml)
print('\n', file = cis_task_yml)

print(f'- name: AUDIT - OUTPUT TO FILE', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'copy:', file = cis_task_yml)
print(alignment*4 + 'content: id,title,compliant_status', file = cis_task_yml)
print(alignment*4 + 'dest: \"{{ role_path }}/files/' + outputs_directory + 'audit_result.csv\"', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- default', file = cis_task_yml)
print('\n', file = cis_task_yml)
print('\n', file = cis_task_yml)

with open(cis_csv,'r') as cis_csv:
    cis_reader = csv.reader(cis_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    cis_list = list(cis_reader)

    for i in range(len(cis_list)):
        recommendation = cis_list[i][recommendation_field_no]
        audit = "{ " + cis_list[i][audit_verified_field_no].replace('\n','; ').replace('\"','\'').replace('\\','\\\\') + "; } | tr \\\\\\\\n \\\|"
        audit_verified = cis_list[i][audit_verified_field_no]
        if line_count == 0:
            line_count += 1
        else:
            if not recommendation == "" and not cis_list[i][audit_verified_field_no] == "":
                cis_files_command_txt = open(roles_files_path + recommendation + '_command.sh', 'w')
                cis_files_output_txt = open(roles_files_path + recommendation + '_output.txt', 'w')

                print("Created Ansible Task For: " + recommendation)
                title = recommendation + " - " + cis_list[i][title_field_no].replace('\n',' ')
                title_output = cis_list[i][title_field_no].replace('\n',' ')
                profile = cis_list[i][profile_field_no]
                assessment_status = cis_list[i][assessment_status_field_no]
                description = cis_list[i][description_field_no].replace('\n','\n# ')
                rationale = cis_list[i][rationale_field_no].replace('\n','\n# ')
                expected_results = cis_list[i][audit_expected_result_field_no].replace('\n','|')
                expected_results_cleanup = expected_results.replace('<No output>','') if "<No output>" in expected_results else expected_results
                expected_results_cleanup = expected_results.replace('Nothing should be returned','') if "Nothing should be returned" in expected_results_cleanup else expected_results_cleanup
                expected_results_cleanup = expected_results_cleanup+"|" if not expected_results_cleanup.endswith("|") else expected_results_cleanup
                expected_results_cleanup = "" if expected_results_cleanup == "|" else expected_results_cleanup

                print(audit_verified, file = cis_files_command_txt)
                print(expected_results_cleanup, file = cis_files_output_txt)

                print('#' * divider_count, file = cis_task_yml)
                print('# ', cis_list[0][title_field_no], ' - ', title, file = cis_task_yml)
                print('# ', cis_list[0][profile_field_no], ': ', profile, file = cis_task_yml)
                print('# ', cis_list[0][description_field_no], ': ', description, file = cis_task_yml)
                print('# ', cis_list[0][rationale_field_no], ': ', rationale, file = cis_task_yml)
                print('\n', file = cis_task_yml)
                print(f'- name: AUDIT - {title}', file = cis_task_yml)
                shell_commands_path = "{{ role_path }}/files/" + recommendation + '_command.sh'
                shell_commands = (alignment*2 + 'shell: "sh ' + shell_commands_path + ' | tr \\\\\\\\n \\\|"')
                print(shell_commands, file = cis_task_yml)
                become = alignment*2 + 'become: true' if audit_verified != '' else ''
                print(become, file = cis_task_yml)
                register = (alignment*2 + 'register: results_' + title.split(' ')[0].replace('.','_')) if audit_verified != '' else ''
                print(register, file = cis_task_yml)
                failed = (alignment*2 + 'failed_when: "results_' + title.split(' ')[0].replace('.','_') + '.rc not in [ 0, 1 ]"') if audit_verified != '' else ''
                print(failed, file = cis_task_yml)
                print(alignment*2 + 'tags:', file = cis_task_yml)
                print(alignment*4 + '- all', file = cis_task_yml)
                print(alignment*4 + '- ' + assessment_status.lower(), file = cis_task_yml)
                print(alignment*4 + '- ' + profile.lower().replace(" ",""), file = cis_task_yml)
                print(alignment*4 + '- section' + recommendation[:1], file = cis_task_yml)
                print('\n', file = cis_task_yml)

                print('- set_fact:', file = cis_task_yml)
                print(alignment*4 + 'compliant_status: "{% if results_' + title.split(' ')[0].replace('.','_') + '.stdout | replace(\' |\',\'|\') | string() == lookup(\'file\', \'files/' + recommendation + '_output.txt\') | string() %}COMPLIANT{% else %}NON_COMPLIANT{% endif %}"', file = cis_task_yml)
#                print(alignment*4 + 'compliant_status: "{% if results_' + title.split(' ')[0].replace('.','_') + '.stdout | length and results_' + title.split(' ')[0].replace('.','_') + '.stdout | replace(\' |\',\'|\') in lookup(\'file\', \'files/' + recommendation + '_output.txt\') %}COMPLIANT{% else %}NON_COMPLIANT{% endif %}"', file = cis_task_yml)
                print(alignment*2 + 'tags:', file = cis_task_yml)
                print(alignment*4 + '- all', file = cis_task_yml)
                print(alignment*4 + '- ' + assessment_status.lower(), file = cis_task_yml)
                print(alignment*4 + '- ' + profile.lower().replace(" ",""), file = cis_task_yml)
                print(alignment*4 + '- section' + recommendation[:1], file = cis_task_yml)
                print('\n', file = cis_task_yml)

                print(f'- name: AUDIT - RESULTS - {title}', file = cis_task_yml)
                print(alignment*2 + 'debug: msg="rc={{ results_' + title.split(' ')[0].replace('.','_') + '.rc }} :- results={{ results_' + title.split(' ')[0].replace('.','_') + '.stdout | replace(\' |\',\'|\') }} :- expected_results=' + expected_results_cleanup.replace('\"','\\"') + ' :- compliant_status={{ compliant_status }}"', file = cis_task_yml)
                print(alignment*2 + 'tags:', file = cis_task_yml)
                print(alignment*4 + '- all', file = cis_task_yml)
                print(alignment*4 + '- ' + assessment_status.lower(), file = cis_task_yml)
                print(alignment*4 + '- ' + profile.lower().replace(" ",""), file = cis_task_yml)
                print(alignment*4 + '- section' + recommendation[:1], file = cis_task_yml)

                print('\n', file = cis_task_yml)
                print(f'- name: AUDIT - OUTPUT TO FILE', file = cis_task_yml)
                become = alignment*2 + 'become: true'
                print(become, file = cis_task_yml)
                print(alignment*2 + 'lineinfile:', file = cis_task_yml)
                print(alignment*4 + 'line: "' + recommendation + ',' + title_output.replace(",","-") + ',{{ compliant_status }}"', file = cis_task_yml)
                print(alignment*4 + 'dest: \"{{ role_path }}/files/' + outputs_directory + 'audit_result.csv\"', file = cis_task_yml)
                print(alignment*2 + 'tags:', file = cis_task_yml)
                print(alignment*4 + '- all', file = cis_task_yml)
                print(alignment*4 + '- ' + assessment_status.lower(), file = cis_task_yml)
                print(alignment*4 + '- ' + profile.lower().replace(" ",""), file = cis_task_yml)
                print(alignment*4 + '- section' + recommendation[:1], file = cis_task_yml)
                print('\n', file = cis_task_yml)
                cis_files_command_txt.close()
                cis_files_output_txt.close()

print('\n', file = cis_task_yml)
print(f'- name: AUDIT - READ AUDIT RESULT', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'read_csv:', file = cis_task_yml)
print(alignment*4 + 'path: \"{{ role_path }}/files/' + outputs_directory + 'audit_result.csv\"', file = cis_task_yml)
print(alignment*2 + 'register: audit_results', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- default', file = cis_task_yml)

print('\n', file = cis_task_yml)
print(f'- name: AUDIT - READ AUDIT RESULT', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'vars:', file = cis_task_yml)
print(alignment*4 + 'audit_result_items: []', file = cis_task_yml)
print(alignment*2 + 'set_fact:', file = cis_task_yml)
print(alignment*4 + 'audit_result_items: "{{ audit_result_items + [{ \'Id\': item.id , \'Title\': item.title, \'Status\': item.compliant_status, \'Severity\': \'CRITICAL\' }]}}"', file = cis_task_yml)
print(alignment*2 + 'loop: "{{ audit_results.list }}"', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- default', file = cis_task_yml)

print('\n', file = cis_task_yml)
print(f'- name: AUDIT - READ AUDIT RESULT', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'debug:', file = cis_task_yml)
print(alignment*4 + 'msg: "{{ audit_result_items }}"', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- default', file = cis_task_yml)

print(f'- name: AUDIT - OUTPUT TO FILE', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
print(alignment*2 + 'copy:', file = cis_task_yml)
print(alignment*4 + 'content: "{{ audit_result_items }}"', file = cis_task_yml)
print(alignment*4 + 'dest: ' + '\"{{ role_path }}/files/' + outputs_directory + 'audit_result.json\"', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- default', file = cis_task_yml)

print('\n', file = cis_task_yml)
print(f'- name: AUDIT - UPDATE TO COMPLIANCE', file = cis_task_yml)
become = alignment*2 + 'become: true'
print(become, file = cis_task_yml)
shell_commands = "aws ssm put-compliance-items --resource-id {{ instance_id.stdout_lines[0] | default(instance_details.json.instanceId) }} --resource-type ManagedInstance --compliance-type \\\"Custom:CISAudit\\\" --execution-summary ExecutionTime=\\\"{{ ansible_date_time.date }} {{ ansible_date_time.time }}\\\",ExecutionType=Command --items file://{{ role_path }}/files/" + outputs_directory + "audit_result.json" + " --region={{ instance_region.stdout_lines[0] | default(instance_details.json.region) }}"
print(alignment*2 + 'shell: "' + shell_commands + '"', file = cis_task_yml)
print(alignment*2 + 'tags:', file = cis_task_yml)
print(alignment*4 + '- all', file = cis_task_yml)
print(alignment*4 + '- upload_compliance_cloud', file = cis_task_yml)
print(alignment*4 + '- upload_compliance_hybrid', file = cis_task_yml)

# aws ssm put-compliance-items \
        # --resource-id i-0c7af7a67d8f15500 \
        # --resource-type ManagedInstance \
        # --compliance-type "Custom:CISAudit" \
        # --execution-summary ExecutionTime="2023-09-13 08:29:05",ExecutionType=Command  \
        # --items file://test.json \
        # --region="ap-southeast-1"
# [
    # {
        # "Id": "0.1.5",
        # "Title": "You are a Prick",
        # "Severity": "CRITICAL",
        # "Status": "COMPLIANT"
    # },
    # {
        # "Id": "0.1.6",
        # "Title": "You are a Prick",
        # "Severity": "CRITICAL",
        # "Status": "COMPLIANT"
    # },
    # {
        # "Id": "0.1.7",
        # "Title": "You are a Prick",
        # "Severity": "CRITICAL",
        # "Status": "COMPLIANT"
    # }
# ]

cis_audit_yml = open(parent_directory+assignment_directory+platform_name+'_'+'cis_audit.yml', 'w')
print(f'- name: CIS Audit', file = cis_audit_yml)
print(f'{alignment*2}hosts: all', file = cis_audit_yml)
print(f'{alignment*2}gather_facts: yes', file = cis_audit_yml)
# print(f'{alignment*2}connection: local', file = cis_audit_yml)
print(f'{alignment*2}roles:', file = cis_audit_yml)
print(f'{alignment*4}- {{ role: '+role+' }', file = cis_audit_yml)

cis_task_yml.close()
cis_audit_yml.close()
cis_csv.close()
host_file.close()

zip_folder_with_shutil(playbook_path,playbook_path)

