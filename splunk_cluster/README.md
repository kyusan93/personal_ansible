## DISCLAMER ##
PROPERTY OF GOH THIAM AIK.
Please do not distribute unless permission is sought..

## Compability ##
Update - Dec 2022 - This Playbook is tested and supports ansible-core 2.13.x and ansible 6.4

## PRE-REQUISITE ##
1. IP Addresses of all Splunk nodes
2. Ansible Tower able to reach all Splunk nodes ip via ssh
3. Update the groupvars/all to suit the environment
4. Update inv-\<TYPE_OF_SETUP\>.yml
5. Store license.lic in roles/common/files/
6. Store certificates in {{ base.awx_tmp_dir }}
7. Store Splunk installer in roles/common/files/installer/
<br/><br/>

## TO RUN ##
<b><u>Generate self signed certificates</u></b>
<br/>
1_self_signed_certificates.yml


<b><u>Prechecks</u></b>
<br/>
2_prechecks.yml


<b><u>Setup splunk</u></b>
<br/>
3_setup_splunk.yml


<b><u>Update signed certificates</u></b>
<br/>
4_trust_signed_certificates.yml


<b><u>Configure Keepalive</u></b>
<br/>
5_configure_keepalive.yml


<b><u>Configure HEC</u></b>
<br/>
5_configure_hec.yml


<b><u>Configure LDAP</u></b>
<br/>
5_configure_ldap.yml


<b><u>Hardening</u></b>
<br/>
6_hardening.yml
<br/>

## ROLES ##

* self_signed_certificates
* base_os
* precheck
* base_splunk ==> license_master ==> cluster_master ==> deployment_server ==> indexer ==> deployer ==> search_head ==> heavy_forwarder ==> monitoring_console
* trust_signed_certificates
* Configure Keepalive
* Configure HEC
* Configure LDAP
* Hardening Check 

## Task list Tracker ##
- [ ] Iptables rules for port 443 routing not persistent after restart
- [ ] Internal log sending not sending to indexers properly
- [ ] Enhancement - configure global-banner
- [ ] Enhancement - add polkit to splunk enable boot-start 
