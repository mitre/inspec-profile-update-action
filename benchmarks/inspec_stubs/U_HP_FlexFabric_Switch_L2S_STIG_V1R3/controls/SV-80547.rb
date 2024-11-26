control 'SV-80547' do
  title 'The HP FlexFabric Switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or by using botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Check if the HP FlexFabric Switch is configured to protect against known DoS attacks by implementing a control plane QoS policy to rate limit specify traffic types destined to the switch. 

[HP] display qos policy control-plane pre-defined

[HP] display qos policy user-defined

If the HP FlexFabric Switch is not configured with a control plane QoS policy, this is a finding.'
  desc 'fix', 'Configure QoS policy and apply it to the control plane:
[HP] traffic classifier Net-Protocols operator and
[HP-classifier Net-Protocols] if-match control-plane protocol icmp
[HP-classifier Net-Protocols] quit
[HP] traffic behavior Net-Protocols
[HP-behavior-Net-Protocols] car cir 320
[HP-behavior-Net-Protocols] quit
[HP] qos policy Net-protocols
[HP-qospolicy-Net-Protocols] classifier Net-Protocols behavior Net-protocols
[HP-qospolicy-Net-Protocols] quit
[HP] control-plane slot 1
[HP-cp-slot1] qos apply policy Net-Protocols inbound

Note: In addition, ACLs can be deployed to address specific types of attacks based on IP, MAC, protocols and ports.
Note: By default, the HP FlexFabric Switches are configured with pre-defined control plane QoS policies, which take effect on the control planes by default.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 L2S'
  tag check_id: 'C-66701r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66057'
  tag rid: 'SV-80547r1_rule'
  tag stig_id: 'HFFS-L2-000006'
  tag gtitle: 'SRG-NET-000193-L2S-000020'
  tag fix_id: 'F-72133r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
