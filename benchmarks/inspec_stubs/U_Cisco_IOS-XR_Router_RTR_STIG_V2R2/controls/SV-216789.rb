control 'SV-216789' do
  title 'The MPLS router with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.'
  desc 'RSVP-TE can be used to perform constraint-based routing when building LSP tunnels within the network core that will support QoS and traffic engineering requirements. RSVP-TE is also used to enable MPLS Fast Reroute, a network restoration mechanism that will reroute traffic onto a backup LSP in case of a node or link failure along the primary path. When there is a disruption in the MPLS core, such as a link flap or router reboot, the result is a significant amount of RSVP signaling, such as "PathErr" and "ResvErr" messages that need to be sent for every LSP using that link.

When RSVP messages are sent out, they are sent either hop by hop or with the router alert bit set in the IP header. This means that every router along the path must examine the packet to determine if additional processing is required for these RSVP messages. If there is enough signaling traffic in the network, it is possible for an interface to receive more packets for its input queue than it can hold, resulting in dropped RSVP messages and hence slower RSVP convergence. Increasing the size of the interface input queue can help prevent dropping packets; however, there is still the risk of having a burst of signaling traffic that can fill the queue. Solutions to mitigate this risk are RSVP message pacing or refresh reduction to control the rate at which RSVP messages are sent. RSVP refresh reduction includes the following features: RSVP message bundling, RSVP Message ID to reduce message processing overhead, reliable delivery of RSVP messages using Message ID,  and summary refresh to reduce the amount of information transmitted every refresh interval.'
  desc 'check', 'Review the router configuration to determine  RSVP messages are rate limited.

Step 1: Determine if MPLS TE is enabled on any interface as shown in the example below.

mpls traffic-eng
 interface GigabitEthernet0/0/0/1
 
Step 2: If MPLS TE is enabled, verify that RSVP messages are rate limited on each interface. The example allows 50 messages per 500 milliseconds.

rsvp
 interface GigabitEthernet0/0/0/1
  signaling rate-limit rate 50 interval 500

Note: The command rsvp msg-pacing has been deprecated by the command ip rsvp signaling rate-limit command.

If the router with RSVP-TE enabled does not have message pacing configured based on the link speed and input queue size of adjacent core routers, this is a finding.'
  desc 'fix', 'Configure the router to rate limit RSVP messages as shown in the example.

RP/0/0/CPU0:R3(config)#rsvp interface g0/0/0/1
RP/0/0/CPU0:R3(config-rsvp-if)#signaling rate-limit rate 50 interval 500
RP/0/0/CPU0:R3(config-rsvp-if)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18021r288744_chk'
  tag severity: 'low'
  tag gid: 'V-216789'
  tag rid: 'SV-216789r531087_rule'
  tag stig_id: 'CISC-RT-000610'
  tag gtitle: 'SRG-NET-000193-RTR-000001'
  tag fix_id: 'F-18019r288745_fix'
  tag 'documentable'
  tag legacy: ['SV-105923', 'V-96785']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
