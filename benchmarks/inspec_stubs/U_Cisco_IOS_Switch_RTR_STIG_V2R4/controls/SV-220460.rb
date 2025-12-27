control 'SV-220460' do
  title 'The Cisco switch must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the switch configuration to determine if it is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks. 

Step 1: Verify that a class-map has been configured for the Scavenger class as shown in the example below: 

class-map match-all SCAVENGER 
 match ip dscp cs1 

Step 2: Verify that the policy-map includes the SCAVENGER class with low priority as shown in the example below: 

policy-map QOS_POLICY 
 class CONTROL_PLANE 
 priority percent 10 
 class C2_VOICE 
 priority percent 10 
 class VOICE 
 priority percent 15 
 class VIDEO 
 bandwidth percent 25 
 class PREFERRED_DATA 
 bandwidth percent 25 
class SCAVENGER 
 bandwidth percent 5 
 class class-default 
 bandwidth percent 10 

Note: Traffic out of profile must be marked at the customer access layer or CE egress edge. 

If the switch is not configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks, this is a finding.'
  desc 'fix', 'Step 1: Configure a class-map for the SCAVENGER class. 

SW1(config)#class-map match-all SCAVENGER 
SW1(config-cmap)#match ip dscp cs1 

Step 2: Add the SCAVENGER class to the policy-map as shown in the example below: 

SW1(config)#policy-map QOS_POLICY 
SW1(config-pmap-c)#no class class-default 
SW1(config-pmap)#class SCAVENGER 
SW1(config-pmap-c)#bandwidth percent 5 
SW1(config-pmap-c)#class class-default 
SW1(config-pmap-c)#bandwidth percent 10 
SW1(config-pmap-c)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22175r508455_chk'
  tag severity: 'medium'
  tag gid: 'V-220460'
  tag rid: 'SV-220460r622190_rule'
  tag stig_id: 'CISC-RT-000780'
  tag gtitle: 'SRG-NET-000193-RTR-000112'
  tag fix_id: 'F-22164r508456_fix'
  tag 'documentable'
  tag legacy: ['SV-110775', 'V-101671']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
