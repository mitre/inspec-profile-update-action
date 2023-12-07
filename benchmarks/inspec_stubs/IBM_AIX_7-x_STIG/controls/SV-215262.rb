control 'SV-215262' do
  title 'AIX must be configured with a default gateway for IPv4 if the system uses IPv4, unless the system is a router.'
  desc 'If a system has no default gateway defined, the system is at increased risk of man-in-the-middle, monitoring, and Denial of Service attacks.'
  desc 'check', 'Check the system for an IPv4 default route using command:
 
# netstat -r |grep default 
default            10.11.20.1       UG        1      1811 en0      -      -

If a default route is not defined, this is a finding.'
  desc 'fix', 'Set a default gateway for IPv4 using:
# route add 0 <ip address of gateway>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16460r294237_chk'
  tag severity: 'medium'
  tag gid: 'V-215262'
  tag rid: 'SV-215262r508663_rule'
  tag stig_id: 'AIX7-00-002063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16458r294238_fix'
  tag 'documentable'
  tag legacy: ['V-91659', 'SV-101757']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
