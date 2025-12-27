control 'SV-235020' do
  title 'The SUSE operating system must prevent Internet Protocol version 6 (IPv6) Internet Control Message Protocol (ICMP) redirect messages from being accepted.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify the SUSE operating system does not accept IPv6 ICMP redirect messages.

Check the value of the IPv6 accept_redirects variable with the following command:

> sudo sysctl net.ipv6.conf.all.accept_redirects
net.ipv6.conf.all.accept_redirects =0

If the network parameter "ipv6.conf.all.accept_redirects" is not equal to "0" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to not accept IPv6 ICMP redirect messages by running the following command as an administrator:

> sudo sysctl -w net.ipv6.conf.all.accept_redirects=0

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38208r619329_chk'
  tag severity: 'medium'
  tag gid: 'V-235020'
  tag rid: 'SV-235020r622137_rule'
  tag stig_id: 'SLES-15-040341'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38171r619330_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
