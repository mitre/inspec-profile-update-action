control 'SV-217070' do
  title 'The Juniper PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.'
  desc 'LDP provides the signaling required for setting up and tearing down pseudowires (virtual circuits used to transport Layer 2 frames) across an MPLS IP core network. Using a targeted LDP session, each PE router advertises a virtual circuit label mapping that is used as part of the label stack imposed on the frames by the ingress PE router during packet forwarding. Authentication provides protection against spoofed TCP segments that can be introduced into the LDP sessions.'
  desc 'check', 'Review the router configuration to determine if LDP messages are being authenticated for the targeted LDP sessions. In the example below, the PE router is LDP peering with remote PE 8.8.8.8.

    ldp {
        interface ge-0/1/0.0;
        interface ge-0/1/1.0;
        session 8.8.8.8 {
            authentication-algorithm hmac-sha-1-96;
            authentication-key-chain LDP_KEY;
        }
    }

If authentication is not being used for the LDP targeted sessions using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Implement authentication for all targeted LDP sessions using a FIPS-approved message authentication code algorithm.

[edit security authentication-key-chains]
set key-chain LDP_KEY key 1 start-time 2018-05-01.12:00 secret xxxxxxxxxxxxx
set key-chain LDP_KEY key 2 start-time 2018-09-01.12:00 secret xxxxxxxxxxxxx
set key-chain LDP_KEY key 3 start-time 2019-01-01.12:00 secret xxxxxxxxxxxxx

[edit protocols ldp]
set session 8.8.8.8 authentication-algorithm hmac-sha-1-96 authentication-key-chain LDP_KEY'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18299r297078_chk'
  tag severity: 'medium'
  tag gid: 'V-217070'
  tag rid: 'SV-217070r639663_rule'
  tag stig_id: 'JUNI-RT-000640'
  tag gtitle: 'SRG-NET-000343-RTR-000001'
  tag fix_id: 'F-18297r297079_fix'
  tag 'documentable'
  tag legacy: ['V-90923', 'SV-101133']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
