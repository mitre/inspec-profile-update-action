control 'SV-234152' do
  title 'The FortiGate firewall must apply ingress filters to traffic that is inbound to the network through any active external interface.'
  desc 'Unrestricted traffic to the trusted networks may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Firewall filters control the flow of network traffic and ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the internet) must be kept separated.'
  desc 'check', 'Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click the Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify the policies are configured for all Interfaces.
4. Verify the polices are configured with Action set either to DENY or ACCEPT based on the organizational requirement.

If a Firewall Policy is not applied to all interfaces, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click the Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New.
4. Name the policy, select Incoming and Outgoing Interfaces.
5. Create the policies with authorized sources and destinations.
6. Create the policies with Action set to either DENY or ACCEPT.
7. Ensure the Enable this policy is toggled to right.
8. Click OK.
9. Ensure a policy is created for each interface.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37337r611454_chk'
  tag severity: 'medium'
  tag gid: 'V-234152'
  tag rid: 'SV-234152r852962_rule'
  tag stig_id: 'FNFG-FW-000115'
  tag gtitle: 'SRG-NET-000364-FW-000031'
  tag fix_id: 'F-37302r611455_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
