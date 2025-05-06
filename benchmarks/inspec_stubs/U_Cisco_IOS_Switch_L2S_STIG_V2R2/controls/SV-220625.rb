control 'SV-220625' do
  title 'The Cisco switch must manage excess bandwidth to limit the effects of packet-flooding types of denial-of-service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet-flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the switch configuration to verify QoS has been enabled as shown below:

mls qos

If QoS has not been enabled, this is a finding.'
  desc 'fix', 'Enable QoS on the switch:

SW1(config)#mls qos'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch L2S'
  tag check_id: 'C-22340r507921_chk'
  tag severity: 'medium'
  tag gid: 'V-220625'
  tag rid: 'SV-220625r539671_rule'
  tag stig_id: 'CISC-L2-000040'
  tag gtitle: 'SRG-NET-000193-L2S-000020'
  tag fix_id: 'F-22329r507922_fix'
  tag 'documentable'
  tag legacy: ['SV-110221', 'V-101117']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
