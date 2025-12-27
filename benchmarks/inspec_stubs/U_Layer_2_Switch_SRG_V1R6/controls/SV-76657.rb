control 'SV-76657' do
  title 'The layer 2 switch must provide the capability for authorized users to select a user session to capture.'
  desc 'Without the capability to select a user session to capture/record or view/hear, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network. Session audits may include port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Verify that the switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session.

If the switch is not capable of capturing ingress and egress packets from a designated switch port, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62167'
  tag rid: 'SV-76657r1_rule'
  tag stig_id: 'SRG-NET-000331-L2S-000001'
  tag gtitle: 'SRG-NET-000331'
  tag fix_id: 'F-68087r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
