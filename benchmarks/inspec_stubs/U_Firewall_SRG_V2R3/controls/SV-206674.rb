control 'SV-206674' do
  title 'The firewall must be configured to use filters that use packet headers and packet attributes, including source and destination IP addresses and ports, to prevent the flow of unauthorized or suspicious traffic between interconnected networks with different security policies (including perimeter firewalls and server VLANs).'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

The firewall that filters traffic outbound to interconnected networks with different security policies must be configured with filters (i.e., rules, access control lists [ACLs], screens, and policies) that permit, restrict, or block traffic based on organization-defined traffic authorizations. Filtering must include packet header and packet attribute information, such as IP addresses and port numbers.

Configure filters to perform certain actions when packets match specified attributes, including the following actions:

- Apply a policy
- Accept, reject, or discard the packets
- Classify the packets based on their source address
- Evaluate the next term in the filter
- Increment a packet counter
- Set the packets’ loss priority
- Specify an IPsec SA (if IPsec is used in the implementation)
- Specify the forwarding path
- Write an alert or message to the system log'
  desc 'check', 'Verify the firewall is configured to use filters to restrict or block information system services based on best practices, known threats, and guidance in the Ports, Protocols, Services Management (PPSM) database regarding restrictions for boundary crossing for ports, protocols, and services.

If the firewall cannot be configured with filters that employ packet header and packet attributes, including source and destination IP addresses and ports, to prevent the flow of unauthorized or suspicious traffic between interconnected networks with different security policies, this is a finding.'
  desc 'fix', 'Configure filters in the firewall to examine characteristics of incoming and outgoing packets, including but not limited to the following:

- Bit fields in the packet header, including IP fragmentation flags, IP options, and TCP flags

- IP version 4 (IPv4) numeric range, including destination port, DiffServ code point (DSCP) value, fragment offset, Internet Control Message Protocol (ICMP) code, ICMP packet type, interface group, IP precedence, packet length, protocol, and TCP and UDP source and destination port

- IP version 6 (IPv6) numeric range, including class of service (CoS) priority, destination address, destination port, ICMP code, ICMP packet type, interface group, IP address, next header, packet length, source address, source port, and TCP and UDP source and destination port

- Source and destination address and prefix list'
  impact 0.7
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6931r297801_chk'
  tag severity: 'high'
  tag gid: 'V-206674'
  tag rid: 'SV-206674r604133_rule'
  tag stig_id: 'SRG-NET-000019-FW-000003'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-6931r297802_fix'
  tag 'documentable'
  tag legacy: ['SV-94115', 'V-79409']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
