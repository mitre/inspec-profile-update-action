control 'SV-90829' do
  title 'The OS X system must not send IPv4 ICMP redirects by default.'
  desc 'ICMP redirects are broadcast to reshape network traffic. A malicious user could use the system to send fake redirect packets and try to force all network traffic to pass through a network sniffer. Disabling ICMP redirect broadcasts mitigates this risk.'
  desc 'check', 'To check if the system is configured to send ICMP redirects, run the following command:

sysctl net.inet.ip.redirect 

If the values are not set to "0", this is a finding.'
  desc 'fix', 'To configure the system to not send ICMP redirects, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.ip.redirect=0'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75827r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76141'
  tag rid: 'SV-90829r1_rule'
  tag stig_id: 'AOSX-12-001210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82779r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
