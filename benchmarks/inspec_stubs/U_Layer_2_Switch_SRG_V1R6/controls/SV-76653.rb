control 'SV-76653' do
  title 'The layer 2 switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or by using botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the switch configuration to verify that QoS has been enabled to ensure that sufficient capacity is available for mission-critical traffic such as voice and enforce the traffic priorities specified by the Combatant Commanders/Services/Agencies.

If the switch is not configured to implement a QoS policy, this is a finding.'
  desc 'fix', 'Implement a QoS policy for traffic prioritization and bandwidth reservation. This policy must enforce the traffic priorities specified by the Combatant Commanders/Services/Agencies.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62967r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62163'
  tag rid: 'SV-76653r1_rule'
  tag stig_id: 'SRG-NET-000193-L2S-000020'
  tag gtitle: 'SRG-NET-000193'
  tag fix_id: 'F-68083r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
