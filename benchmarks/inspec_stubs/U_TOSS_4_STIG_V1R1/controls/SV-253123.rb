control 'SV-253123' do
  title 'TOSS must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default.'
  desc %q(ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

There are notable differences between Internet Protocol version 4 (IPv4) and Internet Protocol version 6 (IPv6). There is only a directive to disable sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of "IPv6 Node Requirements", which resulted in this difference between IPv4 and IPv6.)
  desc 'check', 'Verify TOSS does not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

Check the value of the "default send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.send_redirects

net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.'
  desc 'fix', %q(Configure TOSS to not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default with the following command:

$ sudo sysctl -w net.ipv4.conf.default.send_redirects=0

If "0" is not the system's default value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv4.conf.default.send_redirects=0)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56576r825039_chk'
  tag severity: 'medium'
  tag gid: 'V-253123'
  tag rid: 'SV-253123r825041_rule'
  tag stig_id: 'TOSS-04-040820'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56526r825040_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
