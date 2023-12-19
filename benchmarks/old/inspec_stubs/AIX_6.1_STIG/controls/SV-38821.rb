control 'SV-38821' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', '#no -o ipforwarding
If the value returned is not 0, this is a finding.'
  desc 'fix', 'Disable IPv4 forwarding on the system.
#no  -p -o ipforwarding=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37067r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12023'
  tag rid: 'SV-38821r1_rule'
  tag stig_id: 'GEN005600'
  tag gtitle: 'GEN005600'
  tag fix_id: 'F-32334r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
