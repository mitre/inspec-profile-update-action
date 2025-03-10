control 'SV-220109' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'Determine if the system is configured for IPv4 forwarding.
# svcs | grep svc:/network/ipv4-forwarding
If the service is enabled, this is a finding.'
  desc 'fix', 'Disable IPv4 forwarding on the system.
# svcadm disable svc:/network/ipv4-forwarding'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21818r490144_chk'
  tag severity: 'medium'
  tag gid: 'V-220109'
  tag rid: 'SV-220109r603266_rule'
  tag stig_id: 'GEN005600'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21817r490145_fix'
  tag 'documentable'
  tag legacy: ['V-12023', 'SV-28581']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
