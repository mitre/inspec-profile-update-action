control 'SV-207131' do
  title 'The P router must be configured to enforce a Quality-of-Service (QoS) policy in accordance with the QoS GIG Technical Profile.'
  desc 'Different applications have unique requirements and toleration levels for delay, jitter, bandwidth, packet loss, and availability. To manage the multitude of applications and services, a network requires a QoS framework to differentiate traffic and provide a method to manage network congestion. The Differentiated Services Model (DiffServ) is based on per-hop behavior by categorizing traffic into different classes and enabling each node to enforce a forwarding treatment to each packet as dictated by a policy.

Packet markings such as IP Precedence and its successor, Differentiated Services Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic, prioritizes it according to its relative importance, and provides priority treatment based on the classification. It is imperative that end-to-end QoS is implemented within the IP core network to provide preferred treatment for mission-critical applications.'
  desc 'check', 'Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications in accordance with the QoS GIG Technical Profile. 

Verify that the class-maps are configured to match on DSCP, protocols, or access control lists (ACLs) that identify traffic types based on ports. 

Verify that the policy-map is configured to set DSCP values for the defined class-maps in accordance with the QoS GIG Technical Profile. 

Verify that an input service policy is bound to all interfaces. 

Note: The GTP QOS document (GTP-0009) can be downloaded via the following link:
https://intellipedia.intelink.gov/wiki/Portal:GIG_Technical_Guidance/GTG_GTPs/GTP_Development_List


If the router is not configured to implement a QoS policy in accordance with the QoS GIG Technical Profile, this is a finding.'
  desc 'fix', 'Configure a QoS policy on each router in accordance with the QoS GIG Technical Profile.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7392r539643_chk'
  tag severity: 'low'
  tag gid: 'V-207131'
  tag rid: 'SV-207131r604135_rule'
  tag stig_id: 'SRG-NET-000193-RTR-000114'
  tag gtitle: 'SRG-NET-000193'
  tag fix_id: 'F-7392r539644_fix'
  tag 'documentable'
  tag legacy: ['SV-93027', 'V-78321']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
