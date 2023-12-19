control 'SV-235015' do
  title 'The SUSE operating system must not forward Internet Protocol version 6 (IPv6) source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the SUSE operating system does not accept IPv6 source-routed packets.

Check the value of the IPv6 accept source route variable with the following command:

> sudo sysctl net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route = 0

If the network parameter "ipv6.conf.all.accept_source_route" is not equal to "0" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to disable IPv6 source routing by running the following command as an administrator:

> sudo sysctl -w net.ipv6.conf.all.accept_source_route=0

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv6.conf.all.accept_source_route=0" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38203r619314_chk'
  tag severity: 'medium'
  tag gid: 'V-235015'
  tag rid: 'SV-235015r622137_rule'
  tag stig_id: 'SLES-15-040310'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38166r619315_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
