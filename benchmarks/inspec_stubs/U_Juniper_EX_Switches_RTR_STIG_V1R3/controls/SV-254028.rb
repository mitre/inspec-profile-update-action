control 'SV-254028' do
  title 'The router providing MPLS L2VPN services must be configured to authenticate targeted LDP sessions used to exchange VC information using a FIPS-approved message authentication code algorithm.'
  desc 'Label Distribution Protocol (LDP) provides the signaling required for setting up and tearing down pseudowires (virtual circuits used to transport layer 2 frames) across an MPLS IP core network. Using a targeted LDP session, each PE router advertises a virtual circuit label mapping that is used as part of the label stack imposed on the frames by the ingress PE router during packet forwarding. Authentication provides protection against spoofed TCP segments that can be introduced into the LDP sessions.'
  desc 'check', 'Review the router configuration to determine if LDP messages are being authenticated for the targeted LDP sessions.

[edit protocols]
ldp {
    interface <interface 1 name>.<logical unit>;
    interface <interface 2 name>.<logical unit>;
    session <Session destination address> {
        authentication-algorithm <aes-128-cmac-96|hmac-sha-1-96>;
        authentication-key-chain <name>;
    }
}

If authentication is not being used for the LDP sessions using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Implement authentication for all targeted LDP sessions using a FIPS-approved message authentication code algorithm.

set protocols ldp interface <interface 1 name>.<logical unit>
set protocols ldp interface <interface 2 name>.<logical unit>
set protocols ldp session <Session destination address> authentication-algorithm <aes-128-cmac-96|hmac-sha-1-96>
set protocols ldp session <Session destination address> authentication-key-chain <name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57480r844115_chk'
  tag severity: 'medium'
  tag gid: 'V-254028'
  tag rid: 'SV-254028r844260_rule'
  tag stig_id: 'JUEX-RT-000560'
  tag gtitle: 'SRG-NET-000343-RTR-000001'
  tag fix_id: 'F-57431r844116_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
