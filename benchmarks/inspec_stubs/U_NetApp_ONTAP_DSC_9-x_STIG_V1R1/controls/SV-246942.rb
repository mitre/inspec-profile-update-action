control 'SV-246942' do
  title 'ONTAP must enforce organization-defined role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Use "security login role show" to see role-based access policies defined in ONTAP.

If ONTAP does not enforce organization-defined role-based access control policies over defined subjects and objects, this is a finding.'
  desc 'fix', 'Configure role-based access policies with "security login role create -role <name>" to create new roles, and "security login create -user-or-group-name <user_name> -role <name>" to assign the role to a specific user or group.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50374r769156_chk'
  tag severity: 'medium'
  tag gid: 'V-246942'
  tag rid: 'SV-246942r769158_rule'
  tag stig_id: 'NAOT-CM-000005'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-50328r769157_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (7)']
end
