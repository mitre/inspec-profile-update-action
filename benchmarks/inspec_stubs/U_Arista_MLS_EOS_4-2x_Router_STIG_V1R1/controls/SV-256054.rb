control 'SV-256054' do
  title 'The PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).'
  desc 'An RD provides uniqueness to the customer address spaces within the MPLS L3VPN infrastructure. The concept of the VPN-IPv4 and VPN-IPv6 address families consists of the RD prepended before the IP address. Hence, if the same IP prefix is used in several different L3VPNs, it is possible for BGP to carry several completely different routes for that prefix, one for each VPN.

Since VPN-IPv4 addresses and IPv4 addresses are different address families, BGP never treats them as comparable addresses. The purpose of the RD is to create distinct routes for common IPv4 address prefixes. On any given PE router, a single RD can define a VRF in which the entire address space may be used independently, regardless of the makeup of other VPN address spaces. Hence, it is imperative that a unique RD is assigned to each L3VPN and that the proper RD is configured for each VRF.'
  desc 'check', 'Review the RDs that have been assigned for each VRF according to the plan provided by the ISSM.

Review all VRFs configured on CE-facing interfaces and verify the proper RD has been configured for each.

To verify the proper Route Distinguisher has been configured, execute the command "sh run sec router bgp".
 
router bgp 65000
   vrf PROD
      rd 200:200

If the wrong RD has been configured for any VRF, this is a finding.'
  desc 'fix', 'Configure the correct RD for each VRF.

Configure the correct Route Distinguisher.

PE11(config)#router bgp 65000
PE11(config-router-bgp)#vrf PROD
PE11(config-router-bgp-vrf-PROD)#rd 200:200'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59730r882502_chk'
  tag severity: 'medium'
  tag gid: 'V-256054'
  tag rid: 'SV-256054r882504_rule'
  tag stig_id: 'ARST-RT-000750'
  tag gtitle: 'SRG-NET-000512-RTR-000007'
  tag fix_id: 'F-59673r882503_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
