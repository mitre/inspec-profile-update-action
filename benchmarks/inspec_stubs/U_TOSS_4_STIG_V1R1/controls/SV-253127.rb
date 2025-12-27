control 'SV-253127' do
  title 'TOSS must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify TOSS does not accept IPv6 source-routed packets.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv6.conf.all.accept_source_route

net.ipv6.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.'
  desc 'fix', %q(Configure TOSS to not forward IPv6 source-routed packets with the following command:

$ sudo sysctl -w net.ipv6.conf.all.accept_source_route=0

If "0" is not the system's all value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv6.conf.all.accept_source_route=0)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56580r825051_chk'
  tag severity: 'medium'
  tag gid: 'V-253127'
  tag rid: 'SV-253127r825053_rule'
  tag stig_id: 'TOSS-04-040860'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56530r825052_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
