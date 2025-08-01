control 'SV-16820' do
  title 'There is no VirtualCenter baseline configuration document for users, groups, permissions, and roles.'
  desc 'When pairing users or groups with permissions to an object, a role is defined for users and groups. There are two default roles defined in VirtualCenter called System roles and Sample roles. System roles are permanent and the permissions associated with these roles cannot be changed.  Sample roles are provided for convenience as guidelines and suggestions.  These roles may be modified or removed.  VirtualCenter situations may arise where a user is a member of multiple groups with different permissions or user permissions are explicitly defined when the user is a member of different groups. 

These situations can create confusion and permissions that were thought to be limited might actually be elevated.  Furthermore, all changes take affect immediately not requiring users to log off and log back in. Therefore, all users, groups, permissions, and roles will be documented and approved to ensure proper permissions are granted only to authorized users.'
  desc 'check', 'Request a copy of the baseline configuration document for all VirtualCenter users, groups, permissions, and roles. If the document is incomplete or does not exist, this is a finding.'
  desc 'fix', 'Create a baseline configuration document for all VirtualCenter users, groups, permissions, and roles.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16237r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15879'
  tag rid: 'SV-16820r1_rule'
  tag stig_id: 'ESX0800'
  tag gtitle: 'No VirtualCenter baseline configuration document'
  tag fix_id: 'F-15839r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
