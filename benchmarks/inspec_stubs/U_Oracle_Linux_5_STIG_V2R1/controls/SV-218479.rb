control 'SV-218479' do
  title 'The system must not forward IPv4 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the system does not accept source-routed IPv4 packets.

Procedure:
# grep [01] /proc/sys/net/ipv4/conf/*/accept_source_route|egrep "default|all"

If all of the returned lines do not end with 0, this is a finding.

Note: The same setting is used by Linux for both the local acceptance and forwarding of source-routed IPv4 packets.'
  desc 'fix', 'Configure the system to not accept source-routed IPv4 packets.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.accept_source_route=0" and "net.ipv4.conf.default.accept_source_route=0". 

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19954r562591_chk'
  tag severity: 'medium'
  tag gid: 'V-218479'
  tag rid: 'SV-218479r603259_rule'
  tag stig_id: 'GEN003600'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-19952r562592_fix'
  tag 'documentable'
  tag legacy: ['V-12002', 'SV-64451']
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
