control 'SV-215265' do
  title 'AIX must not have IP forwarding for IPv6 enabled unless the system is an IPv6 router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'From the command prompt, run the following command:

# /usr/sbin/no -o ip6forwarding 
ip6forwarding = 0

If the value returned is not "0", this is a finding.'
  desc 'fix', 'Disable IPv6 forwarding on the system: 
# /usr/sbin/no -p -o ip6forwarding=0'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16463r294246_chk'
  tag severity: 'medium'
  tag gid: 'V-215265'
  tag rid: 'SV-215265r508663_rule'
  tag stig_id: 'AIX7-00-002066'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16461r294247_fix'
  tag 'documentable'
  tag legacy: ['SV-101807', 'V-91709']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
