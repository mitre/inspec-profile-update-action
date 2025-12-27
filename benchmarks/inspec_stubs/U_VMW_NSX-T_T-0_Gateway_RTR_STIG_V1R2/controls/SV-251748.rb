control 'SV-251748' do
  title 'The NSX-T Tier-0 Gateway must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, QoS, or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Segments.

For every Segment connected to a Tier-0 Gateway, Expand Segment >> Expand Segment Profiles >> Record QOS Segment Profile.

Go to Segment Profiles >> Expand QOS Segment Profile recorded in previous steps.

If there are traffic priorities specified by the Combatant Commands/Services/Agencies needed to ensure sufficient capacity for mission-critical traffic and none are configured, this is a finding.'
  desc 'fix', 'To create a segment QoS profile do the following:

From the NSX-T Manager web interface, go to Networking >> Segments >> Segment Profiles.

Click "Add Segment Profile" and select "QoS".

Configure a profile name and QoS settings as needed, and then click "Save".

To apply a QoS profile to a segment do the following:

From the NSX-T Manager web interface, go to Networking >> Segments >> Edit the target segment.

Expand Segment Profiles and under QoS select the profile previously created and click "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55185r810126_chk'
  tag severity: 'medium'
  tag gid: 'V-251748'
  tag rid: 'SV-251748r810128_rule'
  tag stig_id: 'T0RT-3X-000034'
  tag gtitle: 'SRG-NET-000193-RTR-000112'
  tag fix_id: 'F-55139r810127_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
