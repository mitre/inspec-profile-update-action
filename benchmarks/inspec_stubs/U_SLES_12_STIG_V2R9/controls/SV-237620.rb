control 'SV-237620' do
  title 'The SUSE operating system must not forward Internet Protocol version 6 (IPv6) source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the SUSE operating system does not accept IPv6 source-routed packets by default.

Check the value of the default IPv6 accept source route variable with the following command:

> sudo sysctl net.ipv6.conf.default.accept_source_route
net.ipv6.conf.default.accept_source_route = 0

If the network parameter "ipv6.conf.default.accept_source_route" is not equal to "0" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to disable IPv6 default source routing by running the following command as an administrator:

> sudo sysctl -w net.ipv6.conf.default.accept_source_route=0

If "0" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv6.conf.default.accept_source_route=0" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-40839r646821_chk'
  tag severity: 'medium'
  tag gid: 'V-237620'
  tag rid: 'SV-237620r646823_rule'
  tag stig_id: 'SLES-12-030362'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-40802r646822_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
