control 'SV-256052' do
  title 'The PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.'
  desc 'The primary security model for an MPLS L3VPN infrastructure is traffic separation. The service provider must guarantee the customer that traffic from one VPN does not leak into another VPN or into the core, and that core traffic must not leak into any VPN. Hence, it is imperative that each CE-facing interface can only be associated to one VRF—that alone is the fundamental framework for traffic separation.'
  desc 'check', 'Review the design plan for deploying L3VPN and VRF-lite. 

Review all CE-facing interfaces and verify the proper VRF is defined.

To verify the interfaces toward CE facing with proper VRF defined, execute the command "sh run int ethernet YY".

vrf instance PROD
vrf instance DEVP

ip routing vrf PROD
ip routing vrf DEVP

interface Ethernet3
   no routerport
   vrf PROD
   ip address 10.1.99.11/24

interface Ethernet4
   no routerport
   vrf DEVP
   ip address 10.11.5.11/24

If any VRFs are not bound to the appropriate physical or logical interface, this is a finding.'
  desc 'fix', 'Configure the Arista PE router to have each VRF bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.

Configure the VRF on the CE facing interfaces.

PE11(config)#vrf instance PROD
PE11(config)#vrf instance DEVP
!
PE11(config)#ip routing vrf PROD
PE11(config)#ip routing vrf DEVP
!
PE11(config)#interface Ethernet3
PE11(config-if-Et3)#no routerport
PE11(config-if-Et3)#vrf PROD
PE11(config-if-Et3)#ip address 10.1.99.11/24
!
PE11(config)#interface Ethernet4
PE11(config-if-Et3)#no routerport
PE11(config-if-Et3)#vrf DEVP
PE11(config-if-Et3)#ip address 10.11.5.11/24'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59728r882496_chk'
  tag severity: 'high'
  tag gid: 'V-256052'
  tag rid: 'SV-256052r882498_rule'
  tag stig_id: 'ARST-RT-000730'
  tag gtitle: 'SRG-NET-000512-RTR-000005'
  tag fix_id: 'F-59671r882497_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
