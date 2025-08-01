control 'SV-253124' do
  title 'TOSS must not forward IPv4 source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify TOSS does not accept IPv4 source-routed packets by default.

Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_source_route

net.ipv4.conf.default.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.'
  desc 'fix', %q(Configure TOSS to not forward IPv4 source-routed packets by default with the following command:

$ sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

If "0" is not the system's default value then add or update the following line in the appropriate file under "/etc/sysctl.d":

net.ipv4.conf.default.accept_source_route=0)
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56577r825042_chk'
  tag severity: 'medium'
  tag gid: 'V-253124'
  tag rid: 'SV-253124r825044_rule'
  tag stig_id: 'TOSS-04-040830'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56527r825043_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
