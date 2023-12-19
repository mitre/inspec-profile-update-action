control 'SV-216577' do
  title 'The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.'
  desc 'ISPs use BGP to share route information with other autonomous systems (i.e. other ISPs and corporate networks). If the perimeter router was configured to BGP peer with an ISP, NIPRnet routes could be advertised to the ISP, thereby creating a backdoor connection from the Internet to the NIPRnet.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration and verify that it is not BGP peering with an alternate gateway service provider.

Step 1: Determine the ip address of the ISP router 

interface GigabitEthernet0/2
 description Link to ISP
 ip address x.22.1.15 255.255.255.240

Step 2: Verify that the router is not BGP peering with this router.

router bgp nn
 no synchronization
 bgp log-neighbor-changes
 neighbor x.11.1.7 remote-as nn
 neighbor x.11.1.7 password xxxxxxx
 no auto-summary

In the example above, the router is not peering with the ISP.

If the router is BGP peering with an alternate gateway service provider, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Remove any BGP neighbors belonging to the alternate gateway service provider and configure a static route to forward Internet bound traffic to the alternate gateway as shown in the example below.

R5(config)#ip route 0.0.0.0 0.0.0.0 x.22.1.14'
  impact 0.7
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17812r507993_chk'
  tag severity: 'high'
  tag gid: 'V-216577'
  tag rid: 'SV-216577r531085_rule'
  tag stig_id: 'CISC-RT-000290'
  tag gtitle: 'SRG-NET-000019-RTR-000009'
  tag fix_id: 'F-17808r507994_fix'
  tag 'documentable'
  tag legacy: ['SV-105693', 'V-96555']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
