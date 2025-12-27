control 'SV-220627' do
  title 'The Cisco switch must be configured for authorized users to remotely view, in real time, all content related to an established user session from a component separate from the Cisco switch.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.'
  desc 'check', 'Verify that the switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of remotely monitoring a specific user session. 

The example configuration below will capture packets from interface GigabitEthernet0/3 and replicate the packets to interface GigabitEthernet0/2:

monitor session 1 source interface Gi0/3
monitor session 1 destination interface Gi0/2

If the switch is not capable of capturing ingress and egress packets from a designated switch port for the purpose of remotely monitoring a specific user session, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session.

The example configuration below will capture packets from interface GigabitEthernet0/3 and replicate the packets to GigabitEthernet0/2:

SW1(config)#monitor session 1 source int g0/3
SW1(config)#monitor session 1 destination int g0/2'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22342r507927_chk'
  tag severity: 'medium'
  tag gid: 'V-220627'
  tag rid: 'SV-220627r539671_rule'
  tag stig_id: 'CISC-L2-000070'
  tag gtitle: 'SRG-NET-000332-L2S-000002'
  tag fix_id: 'F-22331r507928_fix'
  tag 'documentable'
  tag legacy: ['SV-110225', 'V-101121']
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end
