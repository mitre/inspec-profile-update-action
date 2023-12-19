control 'SV-235022' do
  title 'The SUSE operating system must not allow interfaces to send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology."
  desc 'check', 'Verify the SUSE operating system does not allow interfaces to perform IPv4 ICMP redirects by default.

Check the value of the default IPv4 send_redirects variable with the following command:

> sudo sysctl net.ipv4.conf.default.send_redirects
net.ipv4.conf.default.send_redirects = 0

If the network parameter "ipv4.conf.default.send_redirects" is not equal to "0" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to not allow interfaces to perform IPv4 ICMP redirects by default by running the following command as an administrator:

> sudo sysctl -w net.ipv4.conf.default.send_redirects=0

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38210r619335_chk'
  tag severity: 'medium'
  tag gid: 'V-235022'
  tag rid: 'SV-235022r622137_rule'
  tag stig_id: 'SLES-15-040360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38173r619336_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
