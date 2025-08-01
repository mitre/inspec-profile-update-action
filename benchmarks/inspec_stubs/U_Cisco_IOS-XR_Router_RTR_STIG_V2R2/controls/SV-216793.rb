control 'SV-216793' do
  title 'The Cisco PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).'
  desc 'An RD provides uniqueness to the customer address spaces within the MPLS L3VPN infrastructure. The concept of the VPN-IPv4 and VPN-IPv6 address families consists of the RD prepended before the IP address. Hence, if the same IP prefix is used in several different L3VPNs, it is possible for BGP to carry several completely different routes for that prefix, one for each VPN.

Since VPN-IPv4 addresses and IPv4 addresses are different address families, BGP never treats them as comparable addresses. The purpose of the RD is to create distinct routes for common IPv4 address prefixes. On any given PE router, a single RD can define a VRF in which the entire address space may be used independently, regardless of the makeup of other VPN address spaces. Hence, it is imperative that a unique RD is assigned to each L3VPN and that the proper RD is configured for each VRF.'
  desc 'check', 'Review the design plan for MPLS/L3VPN to determine what RD have been assigned for each VRF. Review the router configuration and verify that the correct RD is configured for each VRF. In the example below, route distinguisher 13:13 has been configured for COI1.

router bgp nn
 address-family ipv4 unicast
 !
 address-family vpnv4 unicast
 !
 …
 …
 …
 !
 vrf COI1
  rd 13:13
  address-family ipv4 unicast
   redistribute ospf 1
  !
 !
!

Note: This requirement is only applicable for MPLS VPN implementations.

If the wrong RD has been configured for any VRF, this is a finding.'
  desc 'fix', 'Configure the correct RD for each VRF.

RP/0/0/CPU0:R3(config)#router bgp nn
RP/0/0/CPU0:R3(config-bgp)#vrf COI1
RP/0/0/CPU0:R3(config-bgp-vrf)#rd 13:13'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18025r288756_chk'
  tag severity: 'medium'
  tag gid: 'V-216793'
  tag rid: 'SV-216793r531087_rule'
  tag stig_id: 'CISC-RT-000650'
  tag gtitle: 'SRG-NET-000512-RTR-000007'
  tag fix_id: 'F-18023r288757_fix'
  tag 'documentable'
  tag legacy: ['SV-105931', 'V-96793']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
