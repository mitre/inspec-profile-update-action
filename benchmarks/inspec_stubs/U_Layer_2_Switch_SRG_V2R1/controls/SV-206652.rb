control 'SV-206652' do
  title 'The layer 2 switch must provide the capability for authorized users to remotely view, in real time, all content related to an established user session from a component separate from the layer 2 switch.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.'
  desc 'check', 'Verify that the switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of remotely monitoring a specific user session.

If the switch is not capable of capturing ingress and egress packets from a designated switch port for the purpose of remotely monitoring a specific user session, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6910r298386_chk'
  tag severity: 'medium'
  tag gid: 'V-206652'
  tag rid: 'SV-206652r383365_rule'
  tag stig_id: 'SRG-NET-000332-L2S-000002'
  tag gtitle: 'SRG-NET-000332'
  tag fix_id: 'F-6910r298387_fix'
  tag 'documentable'
  tag legacy: ['SV-76659', 'V-62169']
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end
