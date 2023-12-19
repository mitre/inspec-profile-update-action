control 'SV-218484' do
  title 'The system must not accept source-routed IPv4 packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the handling of source-routed traffic destined to the system itself, not to traffic forwarded by the system to another system, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the system does not accept source-routed IPv4 packets.

Procedure:
# grep [01] /proc/sys/net/ipv4/conf/*/accept_source_route|egrep "default|all"

If all of the resulting lines do not end with "0", this is a finding.'
  desc 'fix', 'Configure the system to not accept source-routed IPv4 packets.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.accept_source_route=0" and "net.ipv4.conf.default.accept_source_route=0". 

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19959r562594_chk'
  tag severity: 'medium'
  tag gid: 'V-218484'
  tag rid: 'SV-218484r603259_rule'
  tag stig_id: 'GEN003607'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-19957r562595_fix'
  tag 'documentable'
  tag legacy: ['V-22414', 'SV-64197']
  tag cci: ['CCI-001551', 'CCI-001503', 'CCI-000382']
  tag nist: ['AC-4', 'CM-6 d', 'CM-7 b']
end
