control 'SV-88805' do
  title 'The Cisco IOS XE router must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or by botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the Cisco IOS XE router configuration.

Interview the system administrator to verify that Quality of Service (QoS) has been implemented to ensure capacity is available for mission-critical, voice, and control plane traffic during periods of congestion.

The following steps should be used to verify the configuration.

Step 1: Verify that the class-maps are configured to match on DSCP values that have been set at the edges as shown in the configuration example below:

class-map match-all CONTROL_PLANE
match ip dscp 48
class-map match-all C2_VOICE
match ip dscp 47
class-map match-all VOICE
match ip dscp ef
class-map match-all VIDEO
match ip dscp af4
class-map match-all CRITICAL_DATA
match ip dscp af3

Step 2: Verify that the policy map applied to the core-layer-facing interface reserves the bandwidth for each traffic type as shown in the following example:

policy-map QOS_POLICY
class CONTROL_PLANE
priority percent 10
class C2_VOICE
priority percent 10
class VOICE
priority percent 15
class VIDEO
bandwidth percent 25
class CRITICAL_DATA
bandwidth percent 25
class class-default
bandwidth percent 15

Step 3: Verify that an output service policy is bound to the core-layer-facing interface as shown in the configuration example below:

interface GigabitEthernet1/1
 ip address x.x.x.x 255.255.255.0
 service-policy output QOS_POLICY

If QoS policy has not been implemented to ensure there is capacity available for critical, voice, and control plane traffic during periods of congestion, this is a finding.'
  desc 'fix', 'Configure a QOS policy on the Cisco IOS XE router to ensure capacity is available for mission-critical, voice, and control plane traffic during periods of congestion.

The configuration should look similar to the following:

class-map match-all CONTROL_PLANE
match ip dscp 48
class-map match-all C2_VOICE
match ip dscp 47
class-map match-all VOICE
match ip dscp ef
class-map match-all VIDEO
match ip dscp af4
class-map match-all CRITICAL_DATA
match ip dscp af3
…
…
…
policy-map QOS_POLICY
class CONTROL_PLANE
priority percent 10
class C2_VOICE
priority percent 10
class VOICE
priority percent 15
class VIDEO
bandwidth percent 25
class CRITICAL_DATA
bandwidth percent 25
class class-default
bandwidth percent 15
…
…
…
interface GigabitEthernet1/1
 ip address x.x.x.x 255.255.255.0
 service-policy output QOS_POLICY'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74217r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74131'
  tag rid: 'SV-88805r2_rule'
  tag stig_id: 'CISR-RT-000019'
  tag gtitle: 'SRG-NET-000193-RTR-000111'
  tag fix_id: 'F-80673r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
