control 'SV-90823' do
  title 'The OS X system must ignore IPv4 ICMP redirect messages.'
  desc 'ICMP redirects are broadcast to reshape network traffic. A malicious user could craft fake redirect packets and try to force all network traffic to pass through a network sniffer. If the system is not configured to ignore these packets, it could be susceptible to this kind of attack.'
  desc 'check', 'To check if the system is configured to ignore "ICMP redirect" messages, run the following command:

sysctl net.inet.icmp.drop_redirect

If the value is not "1", this is a finding.'
  desc 'fix', 'To configure the system to ignore "ICMP redirect" messages, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.icmp.drop_redirect=1'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75821r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76135'
  tag rid: 'SV-90823r1_rule'
  tag stig_id: 'AOSX-12-001200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82773r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
