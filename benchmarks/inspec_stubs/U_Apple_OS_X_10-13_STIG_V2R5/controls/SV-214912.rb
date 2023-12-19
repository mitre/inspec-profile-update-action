control 'SV-214912' do
  title 'The macOS system must not have IP forwarding for IPv6 enabled.'
  desc 'IP forwarding for IPv6 must not be enabled, as only authorized systems should be permitted to operate as routers.'
  desc 'check', 'To check if "IP forwarding" is enabled, run the following command:

sysctl net.inet6.ip6.forwarding

If the values are not "0", this is a finding.'
  desc 'fix', 'To configure the system to disable "IP forwarding", add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet6.ip6.forwarding=0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16112r397308_chk'
  tag severity: 'medium'
  tag gid: 'V-214912'
  tag rid: 'SV-214912r609363_rule'
  tag stig_id: 'AOSX-13-001206'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16110r397309_fix'
  tag 'documentable'
  tag legacy: ['V-81703', 'SV-96417']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
