control 'SV-214911' do
  title 'The macOS system must not have IP forwarding for IPv4 enabled.'
  desc 'IP forwarding for IPv4 must not be enabled, as only authorized systems should be permitted to operate as routers.'
  desc 'check', 'To check if "IP forwarding" is enabled, run the following command:

sysctl net.inet.ip.forwarding 

If the values are not "0", this is a finding.'
  desc 'fix', 'To configure the system to disable "IP forwarding", add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.ip.forwarding=0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16111r397305_chk'
  tag severity: 'medium'
  tag gid: 'V-214911'
  tag rid: 'SV-214911r609363_rule'
  tag stig_id: 'AOSX-13-001205'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16109r397306_fix'
  tag 'documentable'
  tag legacy: ['V-81701', 'SV-96415']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
