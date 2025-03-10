control 'SV-202092' do
  title 'If the network device uses role-based access control, the network device must enforce organization-defined role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Determine if the network device enforces role-based access control policy over defined subjects and objects.  This requirement may be verified by demonstration, configuration review, or validated test results. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. If role-based access control policy is not enforced over defined subjects and objects, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to enforce role-based access control policy over defined subjects and objects.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2218r381917_chk'
  tag severity: 'medium'
  tag gid: 'V-202092'
  tag rid: 'SV-202092r879706_rule'
  tag stig_id: 'SRG-APP-000329-NDM-000287'
  tag gtitle: 'SRG-APP-000329'
  tag fix_id: 'F-2219r381918_fix'
  tag 'documentable'
  tag legacy: ['SV-69463', 'V-55217']
  tag cci: ['CCI-002169', 'CCI-000366']
  tag nist: ['AC-3 (7)', 'CM-6 b']
end
