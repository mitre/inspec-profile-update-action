control 'SV-207114' do
  title 'The perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.'
  desc 'ISPs use BGP to share route information with other autonomous systems (i.e. other ISPs and corporate networks). If the perimeter router was configured to BGP peer with an ISP, NIPRnet routes could be advertised to the ISP; thereby creating a backdoor connection from the Internet to the NIPRnet.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the configuration of the router connecting to the alternate gateway.

Verify there are no BGP neighbors configured to the remote AS that belongs to the alternate gateway service provider.

If there are BGP neighbors connecting the remote AS of the alternate gateway service provider, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure a static route on the perimeter router to reach the AS of a router connecting to an alternate gateway.'
  impact 0.7
  ref 'DPMS Target Router'
  tag check_id: 'C-7375r382235_chk'
  tag severity: 'high'
  tag gid: 'V-207114'
  tag rid: 'SV-207114r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000009'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7375r382236_fix'
  tag 'documentable'
  tag legacy: ['SV-69987', 'V-55733']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
