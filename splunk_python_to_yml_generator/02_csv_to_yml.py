import contextlib
import csv
import os
import re
import shutil
import sys

if len(sys.argv) < 2:
    print(r"Usage:")
    print(r"python csv_to_yml.py [CSV FILE] [INVENTORY FILE]")
    print(r"python csv_to_yml.py tasks.csv inventory.csv")
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
csv_file = sys.argv[1]
host_file = sys.argv[2]

parent_directory = os.path.expanduser('./')
inventory_directory = "inventory/"
assignment_directory = "ansible_splunk_scripts/"
playbook_path = os.path.join(parent_directory, assignment_directory)

##################
#
# FIELD NUMBERS (Inventory)
#
##################
inv_role_column = 0
inv_ip_address_column = 1
inv_hostname_column = 2
inv_site_column = 3
inv_subrole_column = 4
inv_fqdn_column = 9

##################
#
# FIELD NUMBERS (Tasks)
#
##################
task_section_column = 0
task_subsection_column = 1
task_name_column = 2
task_subname_column = 3
task_host_column = 4
task_script_column = 5

##################
#
# CREATE INVENTORY
#
##################
inventory_path = os.path.join(parent_directory, assignment_directory, inventory_directory)
if not os.path.exists(inventory_path):
            os.makedirs(inventory_path, mode)

csv_inventory_yml = open(inventory_path + 'inventory', 'w')
print('---', file = csv_inventory_yml)
print('all:', file = csv_inventory_yml)
print(alignment*2 + 'children:', file = csv_inventory_yml)

with open(host_file,'r') as host_file:
    host_reader = csv.reader(host_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    host_list = list(host_reader)
    
    line_count = 0

    for i in range(len(host_list)):
        if line_count == 0:
            line_count += 1
        else:
            if host_list[i][inv_role_column] != host_list[i-1][inv_role_column]:
                print('', file = csv_inventory_yml)
                print(alignment*4 + host_list[i][inv_role_column] + ':', file = csv_inventory_yml)
                print(alignment*6 + 'hosts:', file = csv_inventory_yml)

            print(alignment*8 + host_list[i][inv_ip_address_column] + ':', file = csv_inventory_yml)
            print(alignment*10 + 'hostname: ' + host_list[i][inv_hostname_column], file = csv_inventory_yml)
            print(alignment*10 + 'site: ' + host_list[i][inv_site_column], file = csv_inventory_yml)
            print("" if host_list[i][inv_subrole_column] is "" else alignment*10 + 'subrole: ' + host_list[i][inv_subrole_column], file = csv_inventory_yml)

##################
#
# SET VARIABLES BASED ON CSV
#
##################
with open(csv_file,'r') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    csv_list = list(csv_reader)
    
    line_count = 0
    
    for i in range(len(csv_list)):
        if line_count == 0:
            line_count += 1
        else:
            outputs_directory = "outputs/"
            role = csv_list[i][task_name_column].lower().replace(" ","_")
            roles_tasks_directory = 'roles/'+role+'/tasks/'
            roles_files_directory = 'roles/'+role+'/files/'
            all_scripts_directory = 'all_scripts/'

            roles_tasks_path = os.path.join(parent_directory, assignment_directory, roles_tasks_directory)
            roles_files_path = os.path.join(parent_directory, assignment_directory, roles_files_directory)
            all_scripts_path = os.path.join(parent_directory, assignment_directory, all_scripts_directory)

            if not os.path.exists(roles_files_path):
                os.makedirs(roles_files_path, mode)
            if not os.path.exists(roles_tasks_path):
                os.makedirs(roles_tasks_path, mode)
            if not os.path.exists(all_scripts_path):
                os.makedirs(all_scripts_path, mode)
            
            if not csv_list[i][task_name_column] == "":
### PLAYBOOKS
                playbook_filename = csv_list[i][task_section_column] + "-" + csv_list[i][task_name_column]
                playbook_files_txt = open(playbook_path + playbook_filename.lower().replace(" ","_") + '.yml', 'w')
                print('---', file = playbook_files_txt)
                print('- name: ' + csv_list[i][task_name_column], file = playbook_files_txt)
                print(alignment*2 + 'hosts: ' + csv_list[i][task_host_column].lower().replace("\n",","), file = playbook_files_txt)
                print(alignment*2 + 'max_fail_percentage: 0', file = playbook_files_txt)
                print(alignment*2 + 'roles:', file = playbook_files_txt)
                print(alignment*4 + '- { role: ' + csv_list[i][task_name_column] + ' }', file = playbook_files_txt)

### ROLES
                task = csv_list[i][task_section_column] + csv_list[i][task_subsection_column] + "-" + csv_list[i][task_name_column] + "-" + csv_list[i][task_subname_column]
                task_all_scripts = csv_list[i][task_section_column] + csv_list[i][task_subsection_column] + "-" + csv_list[i][task_host_column].replace("\n", ",") + "-" + csv_list[i][task_name_column] + "-" + csv_list[i][task_subname_column]
                csv_files_command_txt = open(roles_files_path + task.lower().replace(" ","_") + '.sh', 'w')
                all_scripts_command_txt = open(all_scripts_path + task_all_scripts.lower().replace(" ","_") + '.sh', 'w')
                
                task_main_file = open(roles_tasks_path + 'main.yml', 'a')
                print('- name: ' + csv_list[i][task_subname_column], file = task_main_file)
                print(alignment*2 + 'script: "{{ playbook_dir }}/roles/' + csv_list[i][task_name_column].lower() + '/files/' + task.lower().replace(" ","_") + '.sh"' , file = task_main_file)
                print('\n', file = task_main_file)

                #title = task + " - " + csv_list[i][task_host_column].replace('\n',' ')
                #title_output = csv_list[i][task_host_column].replace('\n',' ')
                profile = csv_list[i][task_subname_column]
                to_run_script = csv_list[i][task_script_column]

                print(to_run_script, file = csv_files_command_txt)
                print(to_run_script, file = all_scripts_command_txt)
                csv_files_command_txt.close()
                all_scripts_command_txt.close()
                print("Created Shell Script for: " + task)

host_file.close()
csv_file.close()

