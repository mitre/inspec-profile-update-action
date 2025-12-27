control 'SV-75381' do
  title 'The Arista Multilayer Switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or by using botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the router configuration and interview the system administrator; verify that a mechanism for traffic prioritization and bandwidth reservation exists. This arrangement must ensure that sufficient capacity is available for mission-critical traffic and enforce the traffic priorities specified by the Combatant Commanders/Services/Agencies.

To review the configuration, execute a "show qos interfaces" command to see the qos configuration for all interfaces or "show qos interfaces [type] [number] to review the configuration for a specific interface.

QoS must be configured according to organizational policies.

If no such scheme exists or it is not configured, this is a finding.'
  desc 'fix', 'Implement a mechanism for traffic prioritization and bandwidth reservation. This mechanism must enforce the traffic priorities specified by the Combatant Commanders/Services/Agencies.

Arista QoS implementations vary according to the underlying hardware platform. For a complete reference on how to configure QoS for the platform under evaluation, refer to the Arista configuration manual, Chapter 21.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60923'
  tag rid: 'SV-75381r2_rule'
  tag stig_id: 'AMLS-L3-000270'
  tag gtitle: 'SRG-NET-000362-RTR-000110'
  tag fix_id: 'F-66635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
