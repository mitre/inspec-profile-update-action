control 'SV-220652' do
  title 'The Cisco switch must be configured for authorized users to select a user session to capture.'
  desc 'Without the capability to select a user session to capture/record or view/hear, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network. Session audits may include port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Verify that the switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session. The example configuration below will capture packets from interface GigabitEthernet0/3 and replicate the packets to interface GigabitEthernet0/2.

monitor session 1 source interface Gi0/3
monitor session 1 destination interface Gi0/2

If the switch is not capable of capturing ingress and egress packets from a designated switch port, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session. The example configuration below will capture packets from interface GigabitEthernet0/3 and replicate the packets to GigabitEthernet0/2.

SW1(config)#monitor session 1 source int g0/3
SW1(config)#monitor session 1 destination int g0/2'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22367r507504_chk'
  tag severity: 'medium'
  tag gid: 'V-220652'
  tag rid: 'SV-220652r539671_rule'
  tag stig_id: 'CISC-L2-000060'
  tag gtitle: 'SRG-NET-000331-L2S-000001'
  tag fix_id: 'F-22356r507505_fix'
  tag 'documentable'
  tag legacy: ['SV-110275', 'V-101171']
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
