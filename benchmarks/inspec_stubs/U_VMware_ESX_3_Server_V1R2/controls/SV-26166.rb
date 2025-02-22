control 'SV-26166' do
  title 'The system must not have IP forwarding for IPv6 enabled, unless the system is an IPv6 router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'If the system is a router, this is not applicable.
Determine if the system has IPv6 forwarding enabled.  If so, this is a finding.'
  desc 'fix', 'Disable IPv6 forwarding on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22491'
  tag rid: 'SV-26166r1_rule'
  tag stig_id: 'GEN005610'
  tag gtitle: 'GEN005610'
  tag fix_id: 'F-26300r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
