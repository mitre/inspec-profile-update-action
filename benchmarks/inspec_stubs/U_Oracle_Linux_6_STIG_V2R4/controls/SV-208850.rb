control 'SV-208850' do
  title 'The system must not send ICMPv4 redirects by default.'
  desc 'Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers.'
  desc 'check', 'The status of the "net.ipv4.conf.default.send_redirects" kernel parameter can be queried by running the following command: 

$ sysctl net.ipv4.conf.default.send_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 

$ grep net.ipv4.conf.default.send_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.conf.default.send_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.send_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.default.send_redirects = 0)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9103r357530_chk'
  tag severity: 'medium'
  tag gid: 'V-208850'
  tag rid: 'SV-208850r603263_rule'
  tag stig_id: 'OL6-00-000080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9103r357531_fix'
  tag 'documentable'
  tag legacy: ['SV-65167', 'V-50961']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
