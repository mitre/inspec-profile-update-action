control 'SV-215263' do
  title 'IP forwarding for IPv4 must not be enabled on AIX unless the system is a router.'
  desc 'IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.'
  desc 'check', 'From the command prompt, run the following command:

# no -o ipforwarding 
ipforwarding = 0

If the value returned is not "0", this is a finding.'
  desc 'fix', 'Disable IPv4 forwarding on the system by running command:
# no -p -o ipforwarding=0'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16461r294240_chk'
  tag severity: 'medium'
  tag gid: 'V-215263'
  tag rid: 'SV-215263r508663_rule'
  tag stig_id: 'AIX7-00-002064'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16459r294241_fix'
  tag 'documentable'
  tag legacy: ['V-91681', 'SV-101779']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
