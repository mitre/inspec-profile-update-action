control 'SV-234133' do
  title 'The FortiGate firewall must use filters that use packet headers and packet attributes, including source and destination IP addresses and ports.'
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
- Write an alert or message to the system log.'
  desc 'check', 'Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify there are no policies configured with source and destination interface set to "any", and source and destination address set to "all" and the Action set to ACCEPT.

If there are policies configured with source and destination interface set to "any", and source and destination address set to "all" and the Action set to ACCEPT, this is a finding.'
  desc 'fix', 'The fix can be performed on FortiGate GUI or CLI. 
Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New to configure application specific policies, with Action set to ACCEPT.
4. Configure Logging Options to log All Sessions.
5. Confirm each Policy is Enabled.
6. Click OK.

or

1. Open a CLI console, via SSH or available from the GUI.
2. For IPv4 policy, run the following command:
     # config firewall policy
     #   edit {policyid}
     #        set srcintf {interface_name_ext}
     #        set dstintf {interface_name_int}
     #        set srcaddr {address_a}
     #        set dstaddr {address_b}
     #        set schedule {always}
     #        set service {HTTPS}
     #        set action {accept}
     #        set logtraffic all
     # end

For IPv6 policy, run the following command: 
     # config firewall policy6
     #  edit {policyid}
     #        set srcintf {interface_name_ext}
     #        set dstintf {interface_name_int}
     #        set srcaddr {address_a}
     #        set dstaddr {address_b}
     #        set schedule {always}
     #        set service {HTTPS}
     #        set action {accept}
     #        set logtraffic all
     # end

The {} indicate the object is defined by the organization policy. The firewall performs IP integrity header checking on all incoming packets to verify if the protocol packet is a valid TCP, UDP, ICMP, SCTP, or GRE length. Stateful inspection is done to verify TCP SYN and FIN flags are set as needed.'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37318r611397_chk'
  tag severity: 'high'
  tag gid: 'V-234133'
  tag rid: 'SV-234133r611399_rule'
  tag stig_id: 'FNFG-FW-000005'
  tag gtitle: 'SRG-NET-000019-FW-000003'
  tag fix_id: 'F-37283r611398_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
