control 'SV-80551' do
  title 'The HP FlexFabric Switch must provide the capability for authorized users to remotely view, in real time, all content related to an established user session from a component separate from the HP FlexFabric Switch.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.'
  desc 'check', 'Verify that the HP FlexFabric Switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of remotely monitoring a specific user session.

If the HP FlexFabric Switch is not capable of capturing ingress and egress packets from a designated switch port for the purpose of remotely monitoring a specific user session, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to remotely capture ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session as shown in the following example:

[HP]mirroring-group 1 remote-source 

[HP]mirroring-group 1 mirroring-port GigabitEthernet 1/0/1 both

[HP]mirroring-group 1 monitor-port GigabitEthernet 1/0/2'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66705r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66061'
  tag rid: 'SV-80551r1_rule'
  tag stig_id: 'HFFS-L2-000009'
  tag gtitle: 'SRG-NET-000332-L2S-000002'
  tag fix_id: 'F-72137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end
