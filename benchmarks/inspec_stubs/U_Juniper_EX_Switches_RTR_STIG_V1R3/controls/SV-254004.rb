control 'SV-254004' do
  title 'The Juniper MPLS router with RSVP-TE enabled must be configured to enable refresh reduction features.'
  desc 'RSVP-TE can be used to perform constraint-based routing when building LSP tunnels within the network core that will support QoS and traffic engineering requirements. RSVP-TE is also used to enable MPLS Fast Reroute, a network restoration mechanism that will reroute traffic onto a backup LSP in case of a node or link failure along the primary path. When there is a disruption in the MPLS core, such as a link flap or router reboot, the result is a significant amount of RSVP signaling, such as "PathErr" and "ResvErr" messages that need to be sent for every LSP using that link.

When RSVP messages are sent out, they are sent either hop by hop or with the router alert bit set in the IP header. This means that every router along the path must examine the packet to determine if additional processing is required for these RSVP messages. If there is enough signaling traffic in the network, it is possible for an interface to receive more packets for its input queue than it can hold, resulting in dropped RSVP messages and hence slower RSVP convergence. Increasing the size of the interface input queue can help prevent dropping packets; however, there is still the risk of having a burst of signaling traffic that can fill the queue. Solutions to mitigate this risk are RSVP message pacing or refresh reduction to control the rate at which RSVP messages are sent. RSVP refresh reduction includes the following features: RSVP message bundling, RSVP Message ID to reduce message processing overhead, Reliable delivery of RSVP messages using Message ID,  and summary refresh to reduce the amount of information transmitted every refresh interval.'
  desc 'check', %q(Review the router configuration to verify that the router has been configured to enable refresh reduction features. Junos OS controls RSVP refresh reduction features using two commands:

aggregate: RSVP message bundling and summary refresh.
reliable: RSVP message ID, reliable message delivery, and summary refresh.

Starting in Junos 15.2, refresh reduction is enabled by default and the "aggregate" command is deprecated. Configuring the "aggregate" command generates a warning message in the configuration file (## Warning: "aggregate" is deprecated). On Junos earlier than 15.2, verify the "aggregate" command is enabled. On Junos 15.2 and later, no command is required.

Junos earlier than 15.2:
[edit protocols]
rsvp {
    interface <interface name>.<logical unit> {
        aggregate;
        reliable; << If RSVP message ID and reliable message delivery are required.
    }
}

Junos 15.2 but pre-16.1R1:
[edit protocols]
rsvp {
    interface <interface name>.<logical unit> {
        reliable; << If RSVP message ID and reliable message delivery are required.
    }
}

Starting in Junos 16.1R1, all refresh reduction features are enabled by default. Verify the 'no-reliable' command is configured only if RSVP message ID and reliable message delivery are not required. To enable all refresh reduction features, no commands are necessary.

Junos 16.1R1 and later:
[edit protocols]
rsvp {
    interface <interface name>.<logical unit> {
        <other configuration>
    }
}

If the router with RSVP-TE enabled does not have message pacing configured based on the link speed and input queue size of adjacent core routers, this is a finding.)
  desc 'fix', 'Configure RSVP-TE enabled routers with refresh reduction features.

Junos earlier than 15.2:
set protocols rsvp interface <interface name>.<logical unit> aggregate
set protocols rsvp interface <interface name>.<logical unit> reliable

Junos 15.2 but pre 16.1R1:
set protocols rsvp interface <interface name>.<logical unit> reliable

Junos 16.1R1 and later:
set protocols rsvp interface <interface name>.<logical unit> <other configuration>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57456r844043_chk'
  tag severity: 'low'
  tag gid: 'V-254004'
  tag rid: 'SV-254004r844045_rule'
  tag stig_id: 'JUEX-RT-000320'
  tag gtitle: 'SRG-NET-000193-RTR-000001'
  tag fix_id: 'F-57407r844044_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
