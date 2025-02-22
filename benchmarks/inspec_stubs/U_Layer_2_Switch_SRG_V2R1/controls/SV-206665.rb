control 'SV-206665' do
  title 'The layer 2 switch must have all trunk links enabled statically.'
  desc 'When trunk negotiation is enabled via Dynamic Trunk Protocol (DTP), considerable time can be spent negotiating trunk settings (802.1q or ISL) when a node or interface is restored. While this negotiation is happening, traffic is dropped because the link is up from a layer 2 perspective. Packet loss can be eliminated by setting the interface statically to trunk mode, thereby avoiding dynamic trunk protocol negotiation and significantly reducing any outage when restoring a failed link or switch.'
  desc 'check', 'Review the switch configuration to verify that trunk negotiation is disabled by statically configuring all trunk links. Configuring a command to manually disable negotiation may also be required for some switch platforms.

If trunk negotiation is enabled on any interface, this is a finding.'
  desc 'fix', 'Configure the switch to enable trunk links statically.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6923r298425_chk'
  tag severity: 'medium'
  tag gid: 'V-206665'
  tag rid: 'SV-206665r385561_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000005'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6923r298426_fix'
  tag 'documentable'
  tag legacy: ['SV-76687', 'V-62197']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
