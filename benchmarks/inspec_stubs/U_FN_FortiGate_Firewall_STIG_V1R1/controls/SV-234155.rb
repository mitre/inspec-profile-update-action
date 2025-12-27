control 'SV-234155' do
  title 'The FortiGate firewall must restrict traffic entering the VPN tunnels to the management network to only the authorized management packets based on destination address.'
  desc 'Protect the management network with a filtering firewall configured to block unauthorized traffic. This requirement is similar to the out-of-band management (OOBM) model, in which the production network is managed in-band. The management network could also be housed at a Network Operations Center (NOC) that is located locally or remotely at a single or multiple interconnected sites. 

NOC interconnectivity, as well as connectivity between the NOC and the managed networks’ premise routers, would be enabled using either provisioned circuits or VPN technologies such as IPsec tunnels or MPLS VPN services.'
  desc 'check', 'If FortiGate is not configured to support VPN access, this requirement is Not Applicable.

Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify there are Policies where the Incoming Interface is a management-related VPN Tunnel interface, and the Outgoing Interface is the Management Network interface.
4. Verify such policies with Action IPSEC meet organization requirements to only allow connectivity to specific, authorized Management Network hosts and ensure that traffic is encrypted through the IPsec tunnel.
5. Verify at least one of these polices are configured with Action set to DENY.

If there are not DENY Policies in which the Incoming Interface is a management-related VPN Tunnel interface, and the Outgoing Interface is the Management Network interface, this is a finding.

If there are no IPSEC Policies for which the Incoming Interface is a management-related VPN Tunnel interface, and the Outgoing Interface is the Management Network interface that meets organization requirements, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New.
4. Name the policy.
5. For the Incoming Interface, select the tunnel from which a host is connecting to the management network.
6. For the Outgoing Interface, select the interface connected to the management network.
7. For the Source, select the address object or group of authorized management hosts.
8. For the Destination, select assets in the management network, and approved Network Services.
9. Configure the Policy Action to Accept.
10. Ensure Enable this policy is toggled to right.
11. Click OK.

Repeat these steps for each Management Network host and associated Service.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37340r611463_chk'
  tag severity: 'medium'
  tag gid: 'V-234155'
  tag rid: 'SV-234155r628776_rule'
  tag stig_id: 'FNFG-FW-000130'
  tag gtitle: 'SRG-NET-000364-FW-000036'
  tag fix_id: 'F-37305r611464_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
