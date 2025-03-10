control 'SV-79627' do
  title 'If the DataPower Gateway uses role-based access control, the DataPower Gateway must enforce role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Navigate to the DataPower Gateway RBM settings at Administration >> Access >> RBM, Authentication tab using the web interface. Verify that each role is authenticated according to appropriate control policy. If they are not, this is a finding.'
  desc 'fix', 'As the DataPower administrator, configure the DataPower Gateway to enforce role-based access control policy over defined subjects and objects. In the WebGUI, go to Administration >> Access >> RBM Settings. On the Authentication tab, select the approved authentication server. Enter the information required for an authenticated user to access defined subjects and objects.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65137'
  tag rid: 'SV-79627r1_rule'
  tag stig_id: 'WSDP-NM-000089'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-71077r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (7)']
end
