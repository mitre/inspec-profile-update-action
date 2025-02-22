control 'SV-206850' do
  title 'The Voice Video Session Manager supporting Command and Control (C2) communications must limit and reserve bandwidth based on priority of the traffic type.'
  desc 'Without the implementation of safeguards which allocate network communication resources based on priority, network availability, and particularly high priority traffic, may be dropped or delayed. DoD supporting C2 communications relies on the implementation of MLPP to ensure that flag officers and senior staff are provided higher priority for communications than other users. For VoIP and videoconferencing systems, Voice Video Session Managers must communicate using protocols and services that provide expedited packets to users and other systems. Additionally, Quality of Service (QoS) is an effective security safeguard used to ensure network communications availability based on priority. 

Different applications and other network traffic have unique requirements and toleration levels for delay, jitter, bandwidth, packet loss, and availability. To manage the multitude of applications and services, a network requires a QoS framework to differentiate traffic and provide a method to avoid and manage network congestion. When network congestion occurs, all traffic has an equal chance of being dropped. A QoS implementation categorizes network traffic into classes and provides priority treatment based on the classification.'
  desc 'check', 'Verify the Voice Video Session Manager supporting C2 communications limits and reserves bandwidth based on priority of the traffic type.

If the Voice Video Session Manager supporting C2 communications does not limit and reserve bandwidth based on priority of the traffic type, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager supporting C2 communications to limit and reserve bandwidth based on priority of the traffic type.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7105r364739_chk'
  tag severity: 'medium'
  tag gid: 'V-206850'
  tag rid: 'SV-206850r508661_rule'
  tag stig_id: 'SRG-NET-000363-VVSM-00019'
  tag gtitle: 'SRG-NET-000363'
  tag fix_id: 'F-7105r364740_fix'
  tag 'documentable'
  tag legacy: ['SV-76621', 'V-62131']
  tag cci: ['CCI-002394']
  tag nist: ['SC-6']
end
