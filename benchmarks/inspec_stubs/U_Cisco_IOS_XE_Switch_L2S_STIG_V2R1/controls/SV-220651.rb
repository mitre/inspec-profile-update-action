control 'SV-220651' do
  title 'The Cisco switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or by using botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Step 1: Verify that the class-maps are configured to match on DSCP values as shown in the configuration example below:

class-map match-all C2_VOICE
 match ip dscp af47
class-map match-all VOICE
 match ip dscp ef
class-map match-all VIDEO
 match ip dscp af41
class-map match-all PREFERRED_DATA
 match ip dscp af33

Step 2: Verify that the policy map reserves the bandwidth for each traffic type as shown in the following example:

policy-map QOS_POLICY_SWITCHPORT
class C2_VOICE
 priority level 1 10
 class VOICE
 priority level 2 15
 class VIDEO
 bandwidth percent 25
class PREFERRED_DATA
 bandwidth percent 25
 class class-default
 bandwidth percent 25
verone

interface GigabitEthernet1/1
 switchport trunk allowed vlan 100,110,200
switchport mode trunk
 service-policy output QOS_POLICY_SWITCHPORT
!
interface GigabitEthernet1/2
 switchport access vlan 100
 switchport mode access
 switchport voice vlan 200
 trust device cisco-phone
 service-policy output QOS_POLICY_SWITCHPORT
!
interface GigabitEthernet1/2
 switchport access vlan 110
 switchport mode access
 switchport voice vlan 200
 trust device cisco-phone
 service-policy output QOS_POLICY_SWITCHPORT

If QoS has not been enabled, this is a finding.'
  desc 'fix', 'Step 1: Configure class-maps to match on DSCP values as shown in the configuration example below:

SW1(config-cmap)#class-map match-all C2_VOICE
SW1(config-cmap)# match ip dscp 47
SW1(config-cmap)#class-map match-all VOICE
SW1(config-cmap)# match ip dscp ef
SW1(config-cmap)#class-map match-all VIDEO
SW1(config-cmap)# match ip dscp af41
SW1(config)#class-map match-all PREFERRED_DATA
SW1(config-cmap)# match ip dscp af33
SW1(config-cmap)#exit

Step 2: Configure a policy map to be applied to the core-layer-facing interface that reserves the bandwidth for each traffic type as shown in the example below:

SW1(config)#policy-map QOS_POLICY_SWITCHPORT
SW1(config-pmap-c)#class C2_VOICE
SW1(config-pmap-c)# priority level 1 10
SW1(config-pmap-c)#class VOICE
SW1(config-pmap-c)# priority level 2 15
SW1(config-pmap-c)#class VIDEO
SW1(config-pmap-c)#bandwidth percent 25
SW1(config-pmap-c)#class PREFERRED_DATA
SW1(config-pmap-c)#bandwidth percent 25
SW1(config-pmap-c)#class class-default
SW1(config-pmap-c)#bandwidth percent 25
SW1(config-pmap-c)#exit
SW1(config-pmap)#exit

Step 3: Apply the output service policy to the core-layer-facing interface as shown in the configuration example below:

SW1(config)#int g1/1
SW1(config-if)#service-policy output QOS_POLICY_SWITCHPORT
SW1(config-if)#exit
SW1(config)#int g1/2
SW1(config-if)#service-policy output QOS_POLICY_SWITCHPORT
SW1(config-if)#exit
SW1(config)#int g1/3
SW1(config-if)#service-policy output QOS_POLICY_SWITCHPORT
SW1(config-if)#end.'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch L2S'
  tag check_id: 'C-22366r507501_chk'
  tag severity: 'medium'
  tag gid: 'V-220651'
  tag rid: 'SV-220651r539671_rule'
  tag stig_id: 'CISC-L2-000040'
  tag gtitle: 'SRG-NET-000193-L2S-000020'
  tag fix_id: 'F-22355r507502_fix'
  tag 'documentable'
  tag legacy: ['V-101169', 'SV-110273']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
