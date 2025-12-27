control 'SV-208865' do
  title 'The system must ignore ICMPv6 redirects by default.'
  desc 'An illicit ICMP redirect message could result in a man-in-the-middle attack.'
  desc 'check', 'If IPv6 is disabled, this is not applicable.

The status of the "net.ipv6.conf.default.accept_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv6.conf.default.accept_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv6.conf.default.accept_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv6.conf.default.accept_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv6.conf.default.accept_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv6.conf.default.accept_redirects = 0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9118r357575_chk'
  tag severity: 'medium'
  tag gid: 'V-208865'
  tag rid: 'SV-208865r603263_rule'
  tag stig_id: 'OL6-00-000099'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9118r357576_fix'
  tag 'documentable'
  tag legacy: ['SV-64917', 'V-50711']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
