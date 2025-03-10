control 'SV-220056' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'Determine if the system is configured for IPv4 forwarding.
# svcs | grep svc:/network/ipv4-forwarding
If the service is enabled, this is a finding.'
  desc 'fix', 'Disable IPv4 forwarding on the system.
# svcadm disable svc:/network/ipv4-forwarding'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21765r485357_chk'
  tag severity: 'medium'
  tag gid: 'V-220056'
  tag rid: 'SV-220056r603265_rule'
  tag stig_id: 'GEN005600'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21764r485358_fix'
  tag 'documentable'
  tag legacy: ['V-12023', 'SV-28581']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
