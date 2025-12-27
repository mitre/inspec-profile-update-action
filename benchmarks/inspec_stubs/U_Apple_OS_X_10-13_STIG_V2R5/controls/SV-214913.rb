control 'SV-214913' do
  title 'The macOS system must not send IPv4 ICMP redirects by default.'
  desc 'ICMP redirects are broadcast to reshape network traffic. A malicious user could use the system to send fake redirect packets and try to force all network traffic to pass through a network sniffer. Disabling ICMP redirect broadcasts mitigates this risk.'
  desc 'check', 'To check if the system is configured to send ICMP redirects, run the following command:

sysctl net.inet.ip.redirect 

If the values are not set to "0", this is a finding.'
  desc 'fix', 'To configure the system to not send ICMP redirects, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.ip.redirect=0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16113r397311_chk'
  tag severity: 'medium'
  tag gid: 'V-214913'
  tag rid: 'SV-214913r609363_rule'
  tag stig_id: 'AOSX-13-001210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16111r397312_fix'
  tag 'documentable'
  tag legacy: ['SV-96419', 'V-81705']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
