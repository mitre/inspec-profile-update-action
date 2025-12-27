control 'SV-255969' do
  title 'The Arista MLS layer 2 switch must be configured for Storm Control to limit the effects of packet flooding types of denial-of-service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding distributed DOS (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or by using botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).

'
  desc 'check', 'Verify the Arista MLS switch is configured for storm-control on applicable Ethernet interfaces.

switch#show storm-control
Port          Type  Level Rate(Mbps)   Status      Drops Reason
Et10/2         all     75       7500   active          0
Et4   multicast     55       5500   active          0
Et4   broadcast     50       5000   active          
switch#

If the Arista MLS switch is not configured to implement a storm-control policy, this is a finding.'
  desc 'fix', 'The Arista MLS switch must be configured to implement a storm-control policy for traffic prioritization and bandwidth reservation.

Storm-control on switch Ethernet interfaces can be configured to limit the packets based on broadcast, multicast, and unknown-unicast traffic:

switch#configure
switch(config)#internet et[X]
interface Ethernet[X] 
switchport
   storm-control broadcast level pps 5000
   storm-control multicast level pps 5000
   storm-control unknown-unicast level pps 5000'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59645r882247_chk'
  tag severity: 'medium'
  tag gid: 'V-255969'
  tag rid: 'SV-255969r882249_rule'
  tag stig_id: 'ARST-L2-000030'
  tag gtitle: 'SRG-NET-000193-L2S-000020'
  tag fix_id: 'F-59588r882248_fix'
  tag satisfies: ['SRG-NET-000193-L2S-000020', 'SRG-NET-000362-L2S-000024', 'SRG-NET-000512-L2S-000001']
  tag 'documentable'
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 a']
end
