control 'SV-234153' do
  title 'The FortiGate firewall must apply egress filters to traffic outbound from the network through any internal interface.'
  desc 'If outbound communications traffic is not filtered, hostile activity intended to harm other networks or packets from networks destined to unauthorized networks may not be detected and prevented.

Access control policies and access control lists implemented on devices, such as firewalls, that control the flow of network traffic ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the internet) must be kept separated.

This requirement addresses the binding of the egress filter to the interface/zone rather than the content of the egress filter.'
  desc 'check', 'Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click the Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify the policies are configured for each Outgoing Interface.
4. Verify polices are configured with Action set either to DENY or ACCEPT based on the organizational requirement.

If the Firewall Policies are not applied to all outbound interfaces, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click the Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New.
4. Name the policy and select Incoming and Outgoing Interfaces.
5. Create the policies with authorized sources and destinations.
6. Create the policies with Action set to either DENY or ACCEPT.
7. Ensure the Enable this policy is toggled to right.
8. Click OK.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37338r611457_chk'
  tag severity: 'medium'
  tag gid: 'V-234153'
  tag rid: 'SV-234153r628776_rule'
  tag stig_id: 'FNFG-FW-000120'
  tag gtitle: 'SRG-NET-000364-FW-000032'
  tag fix_id: 'F-37303r611458_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
