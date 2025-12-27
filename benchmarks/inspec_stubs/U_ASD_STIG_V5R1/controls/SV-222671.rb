control 'SV-222671' do
  title 'Connections between the DoD enclave and the Internet or other public or commercial wide area networks must require a DMZ.'
  desc 'In order to protect DoD data and systems, all remote access to DoD information systems must be mediated through a managed access control point, such as a remote access server in a DMZ.'
  desc 'check', 'Interview the application representative and determine if the application is publicly accessible.

If the application is publicly accessible and traffic is not being routed through a DMZ, this is a finding.'
  desc 'fix', 'Setup a DMZ between DoD and public networks.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24341r493921_chk'
  tag severity: 'medium'
  tag gid: 'V-222671'
  tag rid: 'SV-222671r508029_rule'
  tag stig_id: 'APSC-DV-003350'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24330r493922_fix'
  tag 'documentable'
  tag legacy: ['V-70421', 'SV-85043']
  tag cci: ['CCI-000366', 'CCI-001119']
  tag nist: ['CM-6 b', 'SC-7 (13)']
end
