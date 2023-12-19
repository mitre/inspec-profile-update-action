control 'SV-255990' do
  title 'The Arista BGP router must be configured to reject inbound route advertisements from a customer edge (CE) router for prefixes that are not allocated to that customer.'
  desc 'As a best practice, a service provider should only accept customer prefixes that have been assigned to that customer and any peering autonomous systems. A multi-homed customer with BGP speaking routers connected to the internet or other external networks could be breached and used to launch a prefix de-aggregation attack. Without ingress route filtering of customers, the effectiveness of such an attack could impact the entire IP core and its customers.'
  desc 'check', 'Review the Arista router configuration to verify filters are defined to only accept routes for prefixes that belong to specific customers. 

The prefix filter must be referenced inbound on the appropriate BGP neighbor statement.

Step 1: Verify the Arista router is configured with ip access-list BGP_Enclave_Gateway_Filter_IN. To verify IP access lists are configured, execute the command "show ip access-lists".

ip access-list BGP_Enclave_Gateway_Filter_IN
 10 permit ip 172.16.50.0/30 any 
 20 permit ip 10.1.1.0/24 any 
 30 permit  ip 12.15.4.9/32 any
 40 deny ip any any log

Step 2: Review the route-map and verify it matches the ACL. To verify route maps are configured, execute the command "show route-map".

route-map FILTER_INBOUND permit 10
   match ip address access-list BGP_Enclave_Gateway_Filter_IN

Step 3: Review the BGP configuration to verify the filter is applied inbound to the appropriate BGP neighbor. To verify the BGP config and verify the route map is applied, execute the command "show run | section router bgp".

router bgp 65001     
 neighbor 100.2.1.1 route-map FILTER_INBOUND in

If the Arista router is not configured to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer, this is a finding.

Note: Routes to PE-CE links within a VPN are needed for troubleshooting end-to-end connectivity across the MPLS/IP backbone. Hence, these prefixes are an exception to this requirement.'
  desc 'fix', 'Step 1: Configure Arista eBGP routers to reject inbound route advertisements from a CE router for prefixes that are not allocated to that specific customer.

LEAF-1A(config)#ip access-list BGP_Enclave_Gateway_Filter_IN
LEAF-1A(config-acl-BGP_Enclave_Gateway_Filter_IN)# 10 permit ip 172.16.50.0/30 any 
LEAF-1A(config-acl-BGP_Enclave_Gateway_Filter_IN)# 20 permit ip 10.1.1.0/24 any  
LEAF-1A(config-acl-BGP_Enclave_Gateway_Filter_IN)# 30 permit  ip 12.15.4.9/32 any
LEAF-1A(config-acl-BGP_Enclave_Gateway_Filter_IN)# 40 deny ip any any log

Step 2: Configure a route-map to match the ACL.

LEAF-1A(config-ip-pfx)#route-map FILTER_INBOUND permit 10
LEAF-1A(config-route-map-FILTER_INBOUND)#match ip address access-list BGP_Enclave_Gateway_Filter_IN

Step 3: Configure the route-map to be applied inbound to the appropriate CE customer neighbor.

LEAF-1A(config)#router bgp 65001     
LEAF-1A(config-router-bgp)#neighbor 100.2.1.1 route-map FILTER_INBOUND in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59666r882310_chk'
  tag severity: 'medium'
  tag gid: 'V-255990'
  tag rid: 'SV-255990r882312_rule'
  tag stig_id: 'ARST-RT-000040'
  tag gtitle: 'SRG-NET-000018-RTR-000004'
  tag fix_id: 'F-59609r882311_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
