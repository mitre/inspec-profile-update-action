control 'SV-207129' do
  title 'The PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the router configuration and interview the System Administrator to verify that a mechanism for traffic prioritization and bandwidth reservation exists.

This arrangement must ensure that sufficient capacity is available for mission-critical traffic and enforce the traffic priorities specified by the Combatant Commands/Services/Agencies.

If no such scheme exists or it is not configured, this is a finding.'
  desc 'fix', 'Implement a mechanism for traffic prioritization and bandwidth reservation. This mechanism must enforce the traffic priorities specified by the Combatant Commands/Services/Agencies.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7390r382325_chk'
  tag severity: 'medium'
  tag gid: 'V-207129'
  tag rid: 'SV-207129r604135_rule'
  tag stig_id: 'SRG-NET-000193-RTR-000112'
  tag gtitle: 'SRG-NET-000193'
  tag fix_id: 'F-7390r382326_fix'
  tag 'documentable'
  tag legacy: ['V-78325', 'SV-93031']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
