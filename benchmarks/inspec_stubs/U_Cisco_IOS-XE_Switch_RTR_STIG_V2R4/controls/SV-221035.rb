control 'SV-221035' do
  title 'The MPLS switch with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core switches.'
  desc 'RSVP-TE can be used to perform constraint-based routing when building LSP tunnels within the network core that will support QoS and traffic engineering requirements. RSVP-TE is also used to enable MPLS Fast Reroute, a network restoration mechanism that will reroute traffic onto a backup LSP in case of a node or link failure along the primary path. When there is a disruption in the MPLS core, such as a link flap or switch reboot, the result is a significant amount of RSVP signaling, such as "PathErr" and "ResvErr" messages that need to be sent for every LSP using that link.

When RSVP messages are sent out, they are sent either hop by hop or with the switch alert bit set in the IP header. This means that every switch along the path must examine the packet to determine if additional processing is required for these RSVP messages. If there is enough signaling traffic in the network, it is possible for an interface to receive more packets for its input queue than it can hold, resulting in dropped RSVP messages and hence slower RSVP convergence. Increasing the size of the interface input queue can help prevent dropping packets; however, there is still the risk of having a burst of signaling traffic that can fill the queue. Solutions to mitigate this risk are RSVP message pacing or refresh reduction to control the rate at which RSVP messages are sent. RSVP refresh reduction includes the following features: RSVP message bundling, RSVP Message ID to reduce message processing overhead, reliable delivery of RSVP messages using Message ID, and summary refresh to reduce the amount of information transmitted every refresh interval.'
  desc 'check', 'Review the switch configuration to determine RSVP messages are rate limited.

Step 1: Determine if MPLS TE is enabled globally and at least one interface as shown in the example below: 

mpls traffic-eng tunnels
…
…
…
interface GigabitEthernet0/2
 no switchport
 ip address x.x.x.x 255.255.255.0
 mpls traffic-eng tunnels
 mpls ip

Step 2: If MPLS TE is enabled, verify that message pacing is enabled.

ip rsvp signalling rate-limit period 30 burst 9 maxsize 2100 limit 50

Note: The command "ip rsvp msg-pacing" has been deprecated by the command "ip rsvp signalling rate-limit". 

If the switch with RSVP-TE enabled does not rate limit RSVP messages based on the link speed and input queue size of adjacent core switches, this is a finding.'
  desc 'fix', 'Configure the switch to rate limit RSVP messages per interface as shown in the example.

SW2(config)#ip rsvp signalling rate-limit burst 9 maxsize 2100 period 30 limit 50'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22750r408899_chk'
  tag severity: 'low'
  tag gid: 'V-221035'
  tag rid: 'SV-221035r622190_rule'
  tag stig_id: 'CISC-RT-000610'
  tag gtitle: 'SRG-NET-000193-RTR-000001'
  tag fix_id: 'F-22739r408900_fix'
  tag 'documentable'
  tag legacy: ['SV-110891', 'V-101787']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
