control 'SV-216806' do
  title 'The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Step 1: Verify that a class map has been configured for the Scavenger class as shown in the example below.

class-map match-all SCAVENGER
 match dscp cs1 
 end-class-map

Step 2: Verify that the policy map includes the SCAVENGER class with low priority as shown in the following example below. 

policy-map QOS_POLICY
 class C2_VOICE
  bandwidth percent 10 
 ! 
 class VOICE
  bandwidth percent 15 
 ! 
 class VIDEO
  bandwidth percent 25 
 ! 
 class CONTROL_PLANE
  bandwidth percent 10 
 ! 
 class PREFERRED_DATA
  bandwidth percent 25 
 ! 
 class SCAVENGER
  bandwidth percent 5 
 ! 
 class class-default
  bandwidth percent 10 
 ! 
 end-policy-map

Note: Traffic out of profile must be marked at the customer access layer or CE egress edge.

If the policy map does not include the SCAVENGER class with low priority, this is a finding.'
  desc 'fix', 'Step 1: Configure a class map for the SCAVENGER class.

RP/0/0/CPU0:R2(config)#class-map match-all SCAVENGER
RP/0/0/CPU0:R2(config-cmap)#match dscp cs1
RP/0/0/CPU0:R2(config-cmap)#exit

Step 2: Add the SCAVENGER class to the policy map as shown in the example below.

RP/0/0/CPU0:R2(config)#policy-map QOS_POLICY
RP/0/0/CPU0:R2(config-pmap)#no class class-default
RP/0/0/CPU0:R2(config-pmap)#class SCAVENGER
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 5
RP/0/0/CPU0:R2(config-pmap-c)#class class-default
RP/0/0/CPU0:R2(config-pmap-c)#bandwidth percent 10
RP/0/0/CPU0:R2(config-pmap-c)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18038r288792_chk'
  tag severity: 'medium'
  tag gid: 'V-216806'
  tag rid: 'SV-216806r531087_rule'
  tag stig_id: 'CISC-RT-000780'
  tag gtitle: 'SRG-NET-000193-RTR-000112'
  tag fix_id: 'F-18036r288793_fix'
  tag 'documentable'
  tag legacy: ['SV-105957', 'V-96819']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
