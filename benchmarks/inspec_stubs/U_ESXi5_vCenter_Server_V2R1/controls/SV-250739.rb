control 'SV-250739' do
  title 'The system must restrict unauthorized vSphere users from being able to execute commands within the guest virtual machine.'
  desc %q(By default, vCenter Server "Administrator" role allows users to interact with files and programs inside a virtual machine's guest operating system. Least Privilege requires that this privilege should not be granted to any users who are not authorized, to reduce risk of Guest confidentiality, availability, or integrity loss. To prevent such loss, a non-guest access role must be created without these privileges. This role is for users who need administrator privileges excluding those allowing file and program interaction within the guests.)
  desc 'check', 'Check that a role is used to manage the vCenter Server without the Guest Access Control (example "Administrator No Guest Access"), and that this role is assigned to administrators who should not have Guest file and program interaction privileges. 

Log into the vCenter Server System using the vSphere Client as a vCenter Server System Administrator. 
Go to "Home>> Administration>> Roles" and verify that a role exists for administrators with Guest access removed. 
Right click on the role name and select "Edit". Verify under "All Privileges>> Virtual Machines" the "Guest Operations" checkbox is unchecked. 
Verify users requiring Administrator privileges without Guest access privileges are assigned to that role and not the default Administrator role.

Ask the SA for a list of users that require administrator privileges without Guest access privileges and verify their role assignments.

If users requiring administrator privileges without Guest access privileges are assigned to the default Administrator role, this is a finding.'
  desc 'fix', 'Create a role to manage vCenter without the Guest Access Control (example "Administrator No Guest Access"), and that this role is assigned to administrators who should not have Guest file and program interaction privileges. 

Log into the vCenter Server System using the vSphere Client as a vCenter Server System Administrator. 
Go to "Home>> Administration>> Roles" and verify a role exists for administrators with Guest access removed. 
Right click on the role name and select "Edit". Verify under "All Privileges>> Virtual Machines" the "Guest Operations" checkbox is unchecked. 
Create account(s) requiring administrator privileges without Guest access privileges.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54174r799905_chk'
  tag severity: 'medium'
  tag gid: 'V-250739'
  tag rid: 'SV-250739r799907_rule'
  tag stig_id: 'VCENTER-000020'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54128r799906_fix'
  tag 'documentable'
  tag legacy: ['V-39558', 'SV-51416']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
