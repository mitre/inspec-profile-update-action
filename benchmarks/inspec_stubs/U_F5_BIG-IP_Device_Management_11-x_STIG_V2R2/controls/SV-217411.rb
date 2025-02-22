control 'SV-217411' do
  title 'The BIG-IP appliance must be configured to enforce organization-defined role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Verify the BIG-IP appliance enforces organization-defined role-based access control policy over defined subjects and objects. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server that assigns authenticated users to an appropriate group.

Navigate to System >> Users >> Remote Role Groups.

Verify Remote Role Groups are assigned proper Role Access and Partition Access.

If the BIG-IP appliance is not configured to enforce organization-defined role-based access control policies over defined subjects and objects, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to enforce organization-defined role-based access control policy over defined subjects and objects.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18636r290787_chk'
  tag severity: 'medium'
  tag gid: 'V-217411'
  tag rid: 'SV-217411r879706_rule'
  tag stig_id: 'F5BI-DM-000179'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-18634r290788_fix'
  tag 'documentable'
  tag legacy: ['SV-74623', 'V-60193']
  tag cci: ['CCI-002169', 'CCI-000366']
  tag nist: ['AC-3 (7)', 'CM-6 b']
end
