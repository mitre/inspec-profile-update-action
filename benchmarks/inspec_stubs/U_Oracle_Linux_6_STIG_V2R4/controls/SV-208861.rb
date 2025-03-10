control 'SV-208861' do
  title 'The system must ignore ICMPv4 bogus error responses.'
  desc 'Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.'
  desc 'check', 'The status of the "net.ipv4.icmp_ignore_bogus_error_responses" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.icmp_ignore_bogus_error_responses

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.icmp_ignore_bogus_error_responses /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.icmp_ignore_bogus_error_responses" kernel parameter, run the following command: 

# sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.icmp_ignore_bogus_error_responses = 1)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9114r357563_chk'
  tag severity: 'low'
  tag gid: 'V-208861'
  tag rid: 'SV-208861r603263_rule'
  tag stig_id: 'OL6-00-000093'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9114r357564_fix'
  tag 'documentable'
  tag legacy: ['SV-64869', 'V-50663']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
