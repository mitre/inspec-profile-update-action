control 'SV-214910' do
  title 'The macOS system must ignore IPv4 ICMP redirect messages.'
  desc 'ICMP redirects are broadcast to reshape network traffic. A malicious user could craft fake redirect packets and try to force all network traffic to pass through a network sniffer. If the system is not configured to ignore these packets, it could be susceptible to this kind of attack.'
  desc 'check', 'To check if the system is configured to ignore "ICMP redirect" messages, run the following command:

sysctl net.inet.icmp.drop_redirect

If the value is not "1", this is a finding.'
  desc 'fix', 'To configure the system to ignore "ICMP redirect" messages, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.icmp.drop_redirect=1'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16110r397302_chk'
  tag severity: 'medium'
  tag gid: 'V-214910'
  tag rid: 'SV-214910r609363_rule'
  tag stig_id: 'AOSX-13-001200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16108r397303_fix'
  tag 'documentable'
  tag legacy: ['V-81699', 'SV-96413']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
