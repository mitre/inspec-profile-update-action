control 'SV-221877' do
  title 'The Oracle Linux operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Verify the system does not respond to IPv4 ICMP echoes sent to a broadcast address.

     # grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null

If "net.ipv4.icmp_echo_ignore_broadcasts" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out, or does not have a value of "1", this is a finding.

Check that the operating system implements the "icmp_echo_ignore_broadcasts" variable with the following command:

     # /sbin/sysctl -a | grep net.ipv4.icmp_echo_ignore_broadcasts
     net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

     net.ipv4.icmp_echo_ignore_broadcasts = 1

Issue the following command to make the changes take effect: 

     # sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23592r880646_chk'
  tag severity: 'medium'
  tag gid: 'V-221877'
  tag rid: 'SV-221877r880648_rule'
  tag stig_id: 'OL07-00-040630'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23581r880647_fix'
  tag 'documentable'
  tag legacy: ['SV-108597', 'V-99493']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
