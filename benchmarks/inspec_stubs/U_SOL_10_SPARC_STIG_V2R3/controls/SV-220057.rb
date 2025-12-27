control 'SV-220057' do
  title 'The system must not have IP forwarding for IPv6 enabled, unless the system is an IPv6 router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'Check if the system is configured for IPv6 forwarding.
# ndd /dev/ip6 ip6_forwarding
If the value is not 0, this is a finding.'
  desc 'fix', 'Disable IPv6 forwarding.
# ndd -set /dev/ip6 ip6_forwarding 0
Edit startup scripts as necessary; add this command or remove commands setting the value to 1.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21766r485360_chk'
  tag severity: 'medium'
  tag gid: 'V-220057'
  tag rid: 'SV-220057r603265_rule'
  tag stig_id: 'GEN005610'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21765r485361_fix'
  tag 'documentable'
  tag legacy: ['SV-26810', 'V-22491']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
