control 'SV-234154' do
  title 'When employed as a premise firewall, FortiGate must block all outbound management traffic.'
  desc "The management network must still have its own subnet in order to enforce control and access boundaries provided by layer 3 network nodes such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. 

Safeguards must be implemented to ensure the management traffic does not leak past the managed network's premise equipment. If a firewall is located behind the premise router, all management traffic must be blocked at that point, with the exception of management traffic destined to premise equipment."
  desc 'check', 'If FortiGate is not employed as a premise firewall, this requirement is Not Applicable.

Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify there are Policies in which the Incoming Interface is the Management Network, and the Outgoing Interface is an EGRESS interface.
4. Verify these polices are configured with Action set to DENY.

If there are not DENY Policies where the Incoming Interface is the Management Network, and the Outgoing Interface is an EGRESS interface, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New.
4. Name the policy.
5. For the Incoming Interface, select the interface related to the Management Network.
6. For the Outgoing Interface, select an EGRESS interface.
7. For the Source, select the Management Network IP range.
8. For the Destination and Service, select ALL.
9. Configure the Policy Action to DENY.
10. Ensure the Enable this policy is toggled to right.
11. Click OK.

Repeat these steps for each EGRESS interface.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37339r611460_chk'
  tag severity: 'medium'
  tag gid: 'V-234154'
  tag rid: 'SV-234154r852965_rule'
  tag stig_id: 'FNFG-FW-000125'
  tag gtitle: 'SRG-NET-000364-FW-000035'
  tag fix_id: 'F-37304r852964_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
