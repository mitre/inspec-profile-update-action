control 'SV-214914' do
  title 'The macOS system must not send IPv6 ICMP redirects by default.'
  desc 'ICMP redirects are broadcast to reshape network traffic. A malicious user could use the system to send fake redirect packets and try to force all network traffic to pass through a network sniffer. Disabling ICMP redirect broadcasts mitigates this risk.'
  desc 'check', 'To check if the system is configured to send ICMP redirects, run the following command:

sysctl net.inet6.ip6.redirect

If the values are not set to "0", this is a finding.'
  desc 'fix', 'To configure the system to not send ICMP redirects, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet6.ip6.redirect=0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16114r397314_chk'
  tag severity: 'medium'
  tag gid: 'V-214914'
  tag rid: 'SV-214914r609363_rule'
  tag stig_id: 'AOSX-13-001211'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16112r397315_fix'
  tag 'documentable'
  tag legacy: ['V-81707', 'SV-96421']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
