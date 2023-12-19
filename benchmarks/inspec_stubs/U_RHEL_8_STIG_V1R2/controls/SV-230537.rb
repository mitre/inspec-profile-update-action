control 'SV-230537' do
  title 'RHEL 8 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echoes facilitates network mapping and provides a vector for amplification attacks.

There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). IPv6 does not implement the same method of broadcast as IPv4. Instead, IPv6 uses multicast addressing to the all-hosts multicast group. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.'
  desc 'check', 'Verify RHEL 8 does not respond to ICMP echoes sent to a broadcast address.

Note: If either IPv4 or IPv6 is disabled on the system, this requirement only applies to the active internet protocol version.

Check the value of the "icmp_echo_ignore_broadcasts" variable with the following command:

$ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", a line is not returned, or the retuned line is commented out, this is a finding.'
  desc 'fix', %q(Configure RHEL 8 to not respond to IPv4 ICMP echoes sent to a broadcast address with the following command:

$ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

If "1" is not the system's default value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv4.icmp_echo_ignore_broadcasts=1)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33206r568357_chk'
  tag severity: 'medium'
  tag gid: 'V-230537'
  tag rid: 'SV-230537r627750_rule'
  tag stig_id: 'RHEL-08-040230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33181r568358_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
