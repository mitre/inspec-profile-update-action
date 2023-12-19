control 'SV-102403' do
  title 'The SEL-2740S -must be configured to limit excess bandwidth and denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch by using readily available tools such as Low Orbit Ion Cannon or by using botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the SEL-2740S to ensure that the meter rules and priorities are in place to ensure mission-critical traffic will not be impacted by increased traffic or bandwidth issues. 

If the SEL-2740S is not configured with meters and priorities necessary for mission-critical packets, this is a finding.'
  desc 'fix', 'Add a flow meter rule to ensure mission-critical traffic will not be impacted.

For adding an SEL-2740S Flow Meter, do the following:
1. Log in to OTSDN Controller using Permission Level 3.
2. Under "Meter Entry" General Settings, select "Meter ID", "Measurement Type", and "Burst Size".
3. Add meter rule to SEL-2740S Flow Rules that require monitoring.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91611r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92315'
  tag rid: 'SV-102403r1_rule'
  tag stig_id: 'SELS-SW-000050'
  tag gtitle: 'SRG-NET-000193-L2S-000020'
  tag fix_id: 'F-98553r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
