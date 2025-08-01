control 'SV-204613' do
  title 'The Red Hat Enterprise Linux operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
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
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4737r880807_chk'
  tag severity: 'medium'
  tag gid: 'V-204613'
  tag rid: 'SV-204613r880809_rule'
  tag stig_id: 'RHEL-07-040630'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4737r880808_fix'
  tag 'documentable'
  tag legacy: ['V-72287', 'SV-86911']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
