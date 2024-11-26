control 'SV-26811' do
  title 'The system must not have IP forwarding for IPv6 enabled, unless the system is an IPv6 router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'Check if the system is configured for IPv6 forwarding.
# ndd -get /dev/ip6 ip6_forwarding

If ip6_forwarding is set to 1, this is a finding.'
  desc 'fix', 'Disable IPv6 forwarding:
# ndd -set /dev/ip6 ip6_forwarding 0

Edit /etc/rc.config.d/nddconf:
TRANSPORT_NAME[index]=ip6
NDD_NAME[index]=ip6_forwarding
NDD_VALUE[index]=0

Where:
	index is the next available integer value of the nddconf file.
	n is a number: either 1 to turn the feature ON or 0 to turn it OFF.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-27799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22491'
  tag rid: 'SV-26811r1_rule'
  tag stig_id: 'GEN005610'
  tag gtitle: 'GEN005610'
  tag fix_id: 'F-24054r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
