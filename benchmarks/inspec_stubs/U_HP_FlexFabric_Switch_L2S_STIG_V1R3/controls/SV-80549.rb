control 'SV-80549' do
  title 'The HP FlexFabric Switch must provide the capability for authorized users to select a user session to capture.'
  desc 'Without the capability to select a user session to capture/record or view/hear, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network. Session audits may include port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Verify that the HP FlexFabric Switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session.

If the HP FlexFabric Switch is not capable of capturing ingress and egress packets from a designated switch port, this is a finding.

[HP]display mirroring-group X
Mirroring group X:

   Type: Remote source
   Status: Active
   Mirroring port: GigabitEthernet1/0/1  Both
   Monitor port: GigabitEthernet1/0/2'
  desc 'fix', 'Configure the HP FlexFabric Switch to capture ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session as shown in the following example:

[HP]mirroring-group 1 local  

[HP]mirroring-group 1 mirroring-port GigabitEthernet 1/0/1 both

[HP]mirroring-group 1 monitor-port GigabitEthernet 1/0/2'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66059'
  tag rid: 'SV-80549r1_rule'
  tag stig_id: 'HFFS-L2-000008'
  tag gtitle: 'SRG-NET-000331-L2S-000001'
  tag fix_id: 'F-72135r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
