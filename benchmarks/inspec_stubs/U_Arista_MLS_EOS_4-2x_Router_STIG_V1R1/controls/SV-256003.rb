control 'SV-256003' do
  title 'The Arista perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.'
  desc 'ISPs use BGP to share route information with other autonomous systems (i.e., other ISPs and corporate networks). If the perimeter router was configured to BGP peer with an ISP, NIPRNet routes could be advertised to the ISP; thereby creating a backdoor connection from the internet to the NIPRNet.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Review the Arista router configuration of the router connecting to the alternate gateway.

To verify no BGP neighbors are configured to the remote AS that belongs to the alternate gateway service provider and the static route is configured, execute the command "show ip route static".

ip route 192.168.67.0/24 12.15.4.9

If BGP neighbors are connecting the remote AS of the alternate gateway service provider, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure a static route on the perimeter router to reach the AS of a router connecting to an alternate gateway.

router(config)#ip route 192.168.67.0/24 12.15.4.9'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59679r882349_chk'
  tag severity: 'high'
  tag gid: 'V-256003'
  tag rid: 'SV-256003r882351_rule'
  tag stig_id: 'ARST-RT-000170'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-59622r882350_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
