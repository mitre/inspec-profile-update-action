control 'SV-217921' do
  title 'The system must not respond to ICMPv4 sent to a broadcast address.'
  desc 'Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.'
  desc 'check', 'The status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

$ grep net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.icmp_echo_ignore_broadcasts = 1

If "net.ipv4.icmp_echo_ignore_broadcasts" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of "1", this is a finding.'
  desc 'fix', 'To set the runtime status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter, run the following command: 

# sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

net.ipv4.icmp_echo_ignore_broadcasts = 1

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19402r376778_chk'
  tag severity: 'low'
  tag gid: 'V-217921'
  tag rid: 'SV-217921r603264_rule'
  tag stig_id: 'RHEL-06-000092'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19400r376779_fix'
  tag 'documentable'
  tag legacy: ['V-38535', 'SV-50336']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
