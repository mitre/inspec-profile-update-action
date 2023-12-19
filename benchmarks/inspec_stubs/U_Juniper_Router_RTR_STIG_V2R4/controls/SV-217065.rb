control 'SV-217065' do
  title 'The Juniper MPLS router with RSVP-TE enabled must be configured to enable refresh reduction features.'
  desc 'RSVP-TE can be used to perform constraint-based routing when building LSP tunnels within the network core that will support QoS and traffic engineering requirements. RSVP-TE is also used to enable MPLS Fast Reroute, a network restoration mechanism that will reroute traffic onto a backup LSP in case of a node or link failure along the primary path. When there is a disruption in the MPLS core, such as a link flap or router reboot, the result is a significant amount of RSVP signaling, such as "PathErr" and "ResvErr" messages that need to be sent for every LSP using that link.

When RSVP messages are sent out, they are sent either hop by hop or with the router alert bit set in the IP header. This means that every router along the path must examine the packet to determine if additional processing is required for these RSVP messages. If there is enough signaling traffic in the network, it is possible for an interface to receive more packets for its input queue than it can hold, resulting in dropped RSVP messages and hence slower RSVP convergence. Increasing the size of the interface input queue can help prevent dropping packets; however, there is still the risk of having a burst of signaling traffic that can fill the queue. Solutions to mitigate this risk are RSVP message pacing or refresh reduction to control the rate at which RSVP messages are sent. RSVP refresh reduction includes the following features: RSVP message bundling, RSVP Message ID to reduce message processing overhead, Reliable delivery of RSVP messages using Message ID,  and summary refresh to reduce the amount of information transmitted every refresh interval.'
  desc 'check', 'Review the router configuration to determine if it is compliant with this requirement. The aggregate reliable commands in the example below will enable the following RSVP refresh reduction features: message bundling, Message ID, reliable message delivery, and summary refresh.

protocols {
    rsvp {
        interface ge-0/0/0.0 {
            aggregate;
            reliable;
        }
    }

If the router configured with RSVP-TE does not have refresh reduction features enabled, this is a finding.'
  desc 'fix', 'Configure the router to enable all refresh reduction features as shown in the example.

[edit protocols rsvp]
set interface ge-0/0/0.0 aggregate reliable

Note: The aggregate reliable commands will enable the following RSVP refresh reduction features: message bundling, reliable message delivery, and summary refresh.'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18294r297063_chk'
  tag severity: 'low'
  tag gid: 'V-217065'
  tag rid: 'SV-217065r604135_rule'
  tag stig_id: 'JUNI-RT-000590'
  tag gtitle: 'SRG-NET-000193-RTR-000001'
  tag fix_id: 'F-18292r297064_fix'
  tag 'documentable'
  tag legacy: ['SV-101123', 'V-90913']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
