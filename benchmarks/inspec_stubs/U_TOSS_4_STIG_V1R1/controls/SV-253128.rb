control 'SV-253128' do
  title 'TOSS must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echoes facilitates network mapping and provides a vector for amplification attacks.

There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). IPv6 does not implement the same method of broadcast as IPv4. Instead, IPv6 uses multicast addressing to the all-hosts multicast group. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.'
  desc 'check', 'Verify TOSS does not respond to ICMP echoes sent to a broadcast address.

Note: If IPv4 is disabled on the system, this requirement is Not Applicable.
Check the value of the "icmp_echo_ignore_broadcasts" variable with the following command:

$ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", a line is not returned, or the retuned line is commented out, this is a finding.'
  desc 'fix', %q(Configure TOSS to not respond to IPv4 ICMP echoes sent to a broadcast address with the following command:

$ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

If "1" is not the system's default value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv4.icmp_echo_ignore_broadcasts=1)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56581r825054_chk'
  tag severity: 'medium'
  tag gid: 'V-253128'
  tag rid: 'SV-253128r825056_rule'
  tag stig_id: 'TOSS-04-040870'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56531r825055_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
