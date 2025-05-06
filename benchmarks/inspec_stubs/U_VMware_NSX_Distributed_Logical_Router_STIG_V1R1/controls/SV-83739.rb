control 'SV-83739' do
  title 'The NSX Distributed Logical Router must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.'
  desc 'Denial of service is a condition when a resource is not available for legitimate users. Packet flooding DDoS attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or by botnets. 
 
Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Verify the traffic shaping policies are properly configured to manage excess bandwidth.

Log into vSphere Web Client with credentials authorized for administration navigate and select Networking >> select the respective VDS under the appropriate datacenter  >> Click the dropdown to expand the list of portgroups >> select the appropriate portgroup for your network.

Navigate to >> Manage >> Settings >> Properties >> Edit >> Traffic Shaping

Verify the necessary values are configured to reserve bandwidth for applications in the event of bandwidth congestion.

Navigate to >> Manage >> Settings >> Properties >> Edit >> Traffic filtering and marking >> Verify the necessary values for DSCP are configured to mark bandwidth for applications in the event of a DoS attack.

Select checkbox for "DSCP value: Update DSCP tag" >> enter in a number between 0 and 63.
Select "+" symbol under Traffic qualifiers with "New System Traffic Qualifier" and select System traffic type >> "OK".
Select "OK" to accept new Network Traffic Rule.

If the traffic shaping and QoS policies are not properly configured to manage excess bandwidth and to reserve bandwidth for critical applications in the event of bandwidth congestion, this is a finding.'
  desc 'fix', 'Log into vSphere Web Client with credentials authorized for administration, navigate and select Networking >> select the respective VDS under the appropriate datacenter  >> Click the dropdown to expand the list of portgroups >> select the appropriate portgroup for your network.  

Navigate to >> Manage >> Settings >> Properties >> Edit >> Traffic Shaping   
Enable traffic shaping for the portgroup.  
Configure average bandwidth, peak bandwidth, and burst size levels as appropriate to provide allocations sufficient to limit the effect of DoS attacks.

Navigate to >> Manage >> Settings >> Properties >> Edit >> Traffic filtering and marking  
Verify the necessary values for DSCP are configured to provide QoS markings to preserve bandwidth for critical applications during periods of congestion.
 
Select checkbox for "DSCP value: Update DSCP tag" >> enter in a number between 0 and 63. 
Select "+" symbol under Traffic qualifiers with "New System Traffic Qualifier" 
Select System traffic type >> "OK".
Select "OK" to accept new Network Traffic Rule.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 RTR'
  tag check_id: 'C-69573r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69135'
  tag rid: 'SV-83739r1_rule'
  tag stig_id: 'VNSX-RT-000019'
  tag gtitle: 'SRG-NET-000193-RTR-000111'
  tag fix_id: 'F-75321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
