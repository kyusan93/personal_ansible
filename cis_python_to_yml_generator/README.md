# CIS-Generator

**Pre-requiste**

RHEL (or similar Linux flavor): version > 8.x

ansible-core: version > 2.11.x

python: version > 3.6

ansible-galaxy collection install community.general


**Steps**
1. Update the CIS csv file with the verified audit commands fields and expected output fields

2. Run the python script to create the Ansible Playbook

`python csv_to_yml.py [CIS CSV FILE]`

`python csv_to_yml.py rhel_9_cis.csv`

Make sure your CIS file ends with '_cis.csv'


3. Run the playbook in the desired nodes

**ANSIBLE COMMANDS**

DEFAULT RUN ALL TASKS [Level 1, Level 2 and upload to aws compliance portal]

`ansible-playbook amazon_linux_2_cis_audit.yml --tags all`

Before running the tasks, get all the tags of the playbook to ensure the tags can be run.

`ansible-playbook rhel_9_cis_audit.yml --list-tags`


RUN TASKS [Level 1 and Level 2]

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level1,level2`
`ansible-playbook rhel_9_cis_audit.yml -i inventory/inv_rhel_9 --extra-vars "ansible_user=ansible-user" --ask-pass --tags default,level1,level2`



RUN TASKS [Level 1]

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level1`



RUN TASKS [Level 2]

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level2`



RUN TASKS [Level 1, Level 2 and upload to aws compliance portal]

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level1,level2,upload_compliance_hybrid`

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level1,level2,upload_compliance_cloud`



RUN TASKS [Level 1 and upload to aws compliance portal]

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level1,upload_compliance_hybrid`

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level1,upload_compliance_cloud`



RUN TASKS [Level 2 and upload to aws compliance portal]

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level2,upload_compliance_hybrid`

`ansible-playbook amazon_linux_2_cis_audit.yml --tags default,level2,upload_compliance_cloud`


