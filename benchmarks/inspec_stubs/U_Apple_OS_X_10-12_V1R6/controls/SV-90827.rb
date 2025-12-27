control 'SV-90827' do
  title 'The OS X system must not have IP forwarding for IPv6 enabled.'
  desc 'IP forwarding for IPv6 must not be enabled, as only authorized systems should be permitted to operate as routers.'
  desc 'check', 'To check if "IP forwarding" is enabled, run the following command:

sysctl net.inet6.ip6.forwarding

If the values are not "0", this is a finding.'
  desc 'fix', 'To configure the system to disable "IP forwarding", add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet6.ip6.forwarding=0'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76139'
  tag rid: 'SV-90827r1_rule'
  tag stig_id: 'AOSX-12-001206'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82777r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
