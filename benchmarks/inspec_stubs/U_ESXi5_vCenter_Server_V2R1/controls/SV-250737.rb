control 'SV-250737' do
  title 'The vCenter Administrator role must be secured and assigned to specific users other than a Windows Administrator.'
  desc "By default, vCenter Server grants full administrative rights to the local administrator's account, which can be accessed by domain administrators. Separation of duties dictates that full vCenter Administrative rights should be granted only to those administrators who are required to have it. This privilege should not be granted to any group whose membership is not strictly controlled. Therefore, administrative rights should be removed from the local Windows administrator account and instead be given to a special-purpose local vCenter Administrator account. This account should be used to create individual user accounts."
  desc 'check', 'Check the permissions assigned  in vSphere. Verify that a non-Windows administrative user account is used to manage vCenter. Ensure the user does not belong to any local groups, such as administrator. 

If a Windows administrative account is used to manage vCenter, this is a finding. 

If the account used to manage vCenter belongs to a local Windows or administrative group, this is a finding.'
  desc 'fix', 'Ensure "Administrator" or any other account or group does not have any privileges except users created as follows: 
Create an ordinary user account that will be used to manage vCenter (example vi-admin). 
Make sure the user does not belong to any local groups, such as administrator. 
 On the top-level hosts and clusters context, log onto vCenter as the Windows administrator; then grant the role of administrator (global vCenter administrator) to the created account. 
Log out of vCenter and log into vCenter with the account created. Verify user is able to perform all tasks available to a vCenter administrator. 
Remove the permissions in the vCenter for the local administrator group.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54172r799899_chk'
  tag severity: 'medium'
  tag gid: 'V-250737'
  tag rid: 'SV-250737r799901_rule'
  tag stig_id: 'VCENTER-000018'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54126r799900_fix'
  tag 'documentable'
  tag legacy: ['V-39556', 'SV-51414']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
