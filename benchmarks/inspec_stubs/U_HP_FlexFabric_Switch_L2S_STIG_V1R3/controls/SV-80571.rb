control 'SV-80571' do
  title 'The HP FlexFabric Switch must have all trunk links enabled statically.'
  desc 'When trunk negotiation is enabled via Dynamic Trunk Protocol (DTP), considerable time can be spent negotiating trunk settings (802.1q or ISL) when a node or interface is restored. While this negotiation is happening, traffic is dropped because the link is up from a layer 2 perspective. Packet loss can be eliminated by setting the interface statically to trunk mode, thereby avoiding dynamic trunk protocol negotiation and significantly reducing any outage when restoring a failed link or switch.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to verify that trunk negotiation is disabled by statically configuring all trunk links. Configuring a command to manually disable negotiation may also be required for some switch platforms.

If trunk negotiation is enabled on any interface, this is a finding.

Sample output:
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan X'
  desc 'fix', 'Configure the HP FlexFabric Switch to enable trunk links statically.

[HP-GigabitEthernet1/0/1]port link-type trunk'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66725r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66081'
  tag rid: 'SV-80571r1_rule'
  tag stig_id: 'HFFS-L2-000022'
  tag gtitle: 'SRG-NET-000512-L2S-000005'
  tag fix_id: 'F-72157r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
