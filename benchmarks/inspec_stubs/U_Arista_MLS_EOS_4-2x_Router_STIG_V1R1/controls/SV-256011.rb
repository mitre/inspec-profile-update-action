control 'SV-256011' do
  title 'The MPLS router with RSVP-TE enabled must be configured with message pacing or refresh reduction to adjust maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.'
  desc 'RSVP-TE can be used to perform constraint-based routing when building LSP tunnels within the network core that will support QoS and traffic engineering requirements. RSVP-TE is also used to enable MPLS Fast Reroute, a network restoration mechanism that will reroute traffic onto a backup LSP in case of a node or link failure along the primary path. When there is a disruption in the MPLS core, such as a link flap or router reboot, the result is a significant amount of RSVP signaling, such as "PathErr" and "ResvErr" messages that need to be sent for every LSP using that link.

When RSVP messages are sent out, they are sent either hop by hop or with the router alert bit set in the IP header. This means that every router along the path must examine the packet to determine if additional processing is required for these RSVP messages. If there is enough signaling traffic in the network, it is possible for an interface to receive more packets for its input queue than it can hold, resulting in dropped RSVP messages and hence slower RSVP convergence. Increasing the size of the interface input queue can help prevent dropping packets; however, there is still the risk of having a burst of signaling traffic that can fill the queue. Solutions to mitigate this risk are RSVP message pacing or refresh reduction to control the rate at which RSVP messages are sent. RSVP refresh reduction includes the following features: RSVP message bundling, RSVP Message ID to reduce message processing overhead, Reliable delivery of RSVP messages using Message ID, and summary refresh to reduce the amount of information transmitted every refresh interval.'
  desc 'check', 'Arista MLS router by default protects RSVP bandwidth by using Refresh Overhead Reduction (RFC 2961).

Review the router configuration to verify the router has been configured to prevent a burst of RSVP traffic engineering signaling messages from overflowing the input queue of any neighbor core router.

The command "refresh method bundled" is the default and enabled, and will not show up in the configuration. However, it can be turned off by "refresh method explicit".

sh run | sec mpls rsvp

mpls rsvp
   refresh method explicit
   no shutdown

If the Arista router is configured with "refresh method explicit" to disable Refresh Overhead Reduction, this is a finding.'
  desc 'fix', 'Configure the router for Refresh Overhead Reduction if using RSVP.

Refresh Overhead Reduction (RFC 2961) can be enabled to support sending message IDs and refreshing state with refresh messages by setting the refresh method to "bundled". 

(config-mpls-rsvp)# no shutdown
(config-mpls-rsvp)# refresh method bundled

This is also the default setting. The above command will reset back to default.'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59687r882373_chk'
  tag severity: 'low'
  tag gid: 'V-256011'
  tag rid: 'SV-256011r882375_rule'
  tag stig_id: 'ARST-RT-000290'
  tag gtitle: 'SRG-NET-000193-RTR-000001'
  tag fix_id: 'F-59630r882374_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
