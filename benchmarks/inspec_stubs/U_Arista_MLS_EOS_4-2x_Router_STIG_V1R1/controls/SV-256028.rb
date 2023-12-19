control 'SV-256028' do
  title 'The PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.'
  desc 'LDP provides the signaling required for setting up and tearing down pseudowires (virtual circuits used to transport Layer 2 frames) across an MPLS IP core network. Using a targeted LDP session, each PE router advertises a virtual circuit label mapping that is used as part of the label stack imposed on the frames by the ingress PE router during packet forwarding. Authentication provides protection against spoofed TCP segments that can be introduced into the LDP sessions.'
  desc 'check', 'Review the Arista router configuration to determine if LDP messages are being authenticated for the targeted LDP sessions.

Step 1: Verify the Arista router configuration to verify LDP is configured globally and router-id is set.

mpls ldp
  router-id [x.x.x.x | interface] LoopbackY
  no shutdown

Step 2: Verify the Arista router configuration to ensure the password is configured for LDP neighbor.

mpls ldp
  password [type] [password]

Step 3: Enable the mpls globally or per interface.

For Global:

mpls ip

For interfaces:

interface Ethernet 1
 mpls ip

If authentication is not being used for the LDP sessions using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Implement authentication for all targeted LDP sessions using a FIPS-approved message authentication code algorithm.

Step 1: Configure the mpls LDP on the Arista MLS.

PE11(config)#mpls ldp
PE11(config-mpls-ldp)#router-id interface Loopback0
PE11(config-mpls-ldp)#no shutdown

Step 2: Enable the authentication for LDP neighbors.

PE11(config-mpls-ldp)#password 0 xxxxx'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59704r882424_chk'
  tag severity: 'medium'
  tag gid: 'V-256028'
  tag rid: 'SV-256028r882426_rule'
  tag stig_id: 'ARST-RT-000480'
  tag gtitle: 'SRG-NET-000343-RTR-000001'
  tag fix_id: 'F-59647r882425_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
