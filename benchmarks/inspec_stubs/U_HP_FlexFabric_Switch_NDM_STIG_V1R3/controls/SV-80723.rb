control 'SV-80723' do
  title 'If the HP FlexFabric Switch uses role-based access control, the HP FlexFabric Switch must enforce organization-defined role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Check the HP FlexFabric Switch to determine if organization-defined discretionary access control policies are enforced over defined subjects and objects.

[HP] display local-user

local-user test
 authorization-attribute user-role network-operator

If organization-defined discretionary access control policies are not enforced over defined subjects and objects, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce organization-defined discretionary access control policies over defined subjects and objects.
Below is an example of a test user being assigned pre-defined user-role network-operator:

[HP] local-user test
[HP-luser-test] authorization-attribute user-role network-operator'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66233'
  tag rid: 'SV-80723r1_rule'
  tag stig_id: 'HFFS-ND-000089'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-72309r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (7)']
end
