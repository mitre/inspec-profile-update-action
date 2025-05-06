control 'SV-217034' do
  title 'The Juniper perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.'
  desc 'ISPs use BGP to share route information with other autonomous systems (i.e. other ISPs and corporate networks). If the perimeter router was configured to BGP peer with an ISP, NIPRNet routes could be advertised to the ISP; thereby creating a backdoor connection from the Internet to the NIPRNet.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the protocols hierarchy in the router configuration (see example below) and verify there are no BGP neighbors configured to a peer AS that belongs to the alternate gateway service provider.

protocols {
    bgp {
        group AS_2 {
            type external;
            peer-as 2;
            neighbor x.x.x.x {
                authentication-algorithm hmac-sha-1-96;
                authentication-key-chain BGP_KEY;
            }
            neighbor x.x.x.x {
                authentication-algorithm hmac-sha-1-96;
                authentication-key-chain BGP_KEY;
            }
        }
    }

If there are BGP neighbors connecting to a peer AS of the alternate gateway service provider, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure a static route on the perimeter router to reach the AS of a router connecting to an alternate gateway as shown in the example below.

[edit routing-options]
set static route 0.0.0.0/0 next-hop x.x.x.x'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18263r296970_chk'
  tag severity: 'high'
  tag gid: 'V-217034'
  tag rid: 'SV-217034r604135_rule'
  tag stig_id: 'JUNI-RT-000290'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-18261r296971_fix'
  tag 'documentable'
  tag legacy: ['SV-101063', 'V-90853']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
