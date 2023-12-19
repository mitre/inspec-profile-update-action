control 'SV-255989' do
  title 'The Arista BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc 'Accepting route advertisements belonging to the local AS can result in traffic looping or being black holed, or at a minimum using a non-optimized path.'
  desc 'check', 'Review the Arista router configuration to verify that it will reject routes belonging to the local AS.

The prefix filter must be referenced inbound on the appropriate BGP neighbor statements.

Step 1: Review the prefix lists configured on the router to filter the local AS prefix (10.12.0.0/16). To verify IP prefix lists are configured, execute the command "show ip prefix-list".

router#sh ip prefix-list
router#ip prefix-list LOCAL_SCOPE_BOUNDARY
   seq 10 deny 10.12.0.0/16
   seq  100 permit  0.0.0.0/0 le32

Step 2: Review the BGP configuration to verify the prefix filter is applied inbound to the BGP neighbor. To verify the BGP config and verify the prefix is applied, execute the command "show run | section router bgp".

router bgp 65000
  router-id 10.11.11.11
  address-family ipv4
    no neighbor 10.11.12.2 prefix-list out     
    neighbor 10.12.0.0 prefix-list LOCAL_SCOPE_BOUNDARY in

If the Arista router is not configured to reject inbound route advertisements belonging to the local AS, this is a finding.'
  desc 'fix', 'Configure Arista eBGP routers to reject inbound route advertisements for prefixes that are not allocated to that specific customer.

Step 1: Configure the prefix-list to reject inbound route advertisements belonging to the local AS.

router(config)#ip prefix-list LOCAL_SCOPE_BOUNDARY
router(config-ip-pfx)#seq 10 deny 10.12.0.0/16
router(config-ip-pfx)#seq 100 permit 0.0.0.0/0 le32
 
Step 2: Configure a route-map to match the prefix-list.

router(config)#route-map LOCAL_AS deny
router(config-route-map-LOCAL_AS)#match IP address prefix-list LOCAL_SCOPE_BOUNDARY
router(config-route-map-LOCAL_AS)#exit

Step 3: Configure the route-map to be applied inbound to the appropriate BGP neighbor.

router(config)#router bgp 65000
router(config-router-bgp)#neighbor 10.12.0.0 prefix-list LOCAL_SCOPE_BOUNDARY in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59665r882307_chk'
  tag severity: 'medium'
  tag gid: 'V-255989'
  tag rid: 'SV-255989r882309_rule'
  tag stig_id: 'ARST-RT-000030'
  tag gtitle: 'SRG-NET-000018-RTR-000003'
  tag fix_id: 'F-59608r882308_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
