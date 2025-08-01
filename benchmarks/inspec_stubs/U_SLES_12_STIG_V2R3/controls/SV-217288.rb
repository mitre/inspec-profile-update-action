control 'SV-217288' do
  title 'The SUSE operating system must not forward Internet Protocol version 6 (IPv6) source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the SUSE operating system does not accept IPv6 source-routed packets.

Check the value of the accept source route variable with the following command:

# sudo sysctl net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to not accept IPv6 source-routed packets by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):

net.ipv6.conf.all.accept_source_route = 0

Run the following command to apply this value:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18516r370020_chk'
  tag severity: 'medium'
  tag gid: 'V-217288'
  tag rid: 'SV-217288r603262_rule'
  tag stig_id: 'SLES-12-030361'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18514r370021_fix'
  tag 'documentable'
  tag legacy: ['V-81803', 'SV-96517']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
