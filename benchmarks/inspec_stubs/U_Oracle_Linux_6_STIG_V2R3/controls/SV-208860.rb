control 'SV-208860' do
  title 'The system must not respond to ICMPv4 sent to a broadcast address.'
  desc 'Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.'
  desc 'check', 'The status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.icmp_echo_ignore_broadcasts

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter, run the following command: 

# sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.icmp_echo_ignore_broadcasts = 1)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9113r357560_chk'
  tag severity: 'low'
  tag gid: 'V-208860'
  tag rid: 'SV-208860r603263_rule'
  tag stig_id: 'OL6-00-000092'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9113r357561_fix'
  tag 'documentable'
  tag legacy: ['SV-64863', 'V-50657']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
