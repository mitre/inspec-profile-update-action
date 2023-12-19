control 'SV-88809' do
  title 'The Cisco IOS XE router must restrict BGP connections to known IP addresses of neighbor routers from trusted Autonomous Systems (AS).'
  desc 'Advertisement of routes by an Autonomous System for networks that do not belong to any of its trusted peers pulls traffic away from the authorized network. This causes a DoS on the network that allocated the block of addresses and may cause a DoS on the network that is inadvertently advertising it as the originator. It is also possible that a misconfigured or compromised router within the network could redistribute Interior Gateway Protocol routes into Border Gateway Protocol, thereby leaking internal routes.'
  desc 'check', 'Review the router configuration and compare it against the network documentation (topology diagrams and peering agreements).

Verify that each BGP peering session is configured with the correct IP address and remote Autonomous System Number (ASN).

If any BGP peering session is not configured with the correct IP address and remote Autonomous System Number (ASN), this is a finding.'
  desc 'fix', 'Configure each BGP peering session to the specific IP address of the peer router and remote Autonomous System Number (ASN) assigned to the organization controlling that peer.'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74135'
  tag rid: 'SV-88809r2_rule'
  tag stig_id: 'CISR-RT-000021'
  tag gtitle: 'SRG-NET-000195-RTR-000086'
  tag fix_id: 'F-80677r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
