control 'SV-255996' do
  title 'The Arista BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  desc 'Verifying the path a route has traversed will ensure that the local AS is not used as a transit network for unauthorized traffic. To ensure that the local AS does not carry any prefixes that do not belong to any customers, all PE routers must be configured to reject routes with an originating AS other than that belonging to the customer.'
  desc 'check', 'This requirement is not applicable for the DODIN backbone. 

Review the Arista router configuration to verify the router is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Step 1: Review the router configuration and verify an as-path access-list statement is defined to only accept routes from a CE router whose AS did not originate the route. 

show ip as-path access-list

ip as-path regex-mode asn
  ip as-path access-list NEIGHBOR_PATH permit ^35121$ any
  ip as-path access-list NEIGHBOR_PATH deny .* any

Step 2: Verify the as-path access list is referenced by the filter-list inbound for the appropriate BGP neighbors.

The filter-list CLI is not supported in Arista MLS. The workaround with route-map follows:

route-map TrafficOtherAS_Path permit 10
 match as-path NEIGHBOR_PATH
 
Step 3: To verify the BGP config and verifying the route map is applied inbound execute the command "show run | sec router bgp".

router bgp 65000
   neighbor 10.1.12.2 route-map TrafficOtherAS_Path in

If the Arista router is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, this is a finding.'
  desc 'fix', 'Configure the Arista router to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Step 1: Configure the as-path access-list to filter the updates from the CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

router (config) # ip as-path regex-mode asn
router (config) # ip as-path access-list NEIGHBOR_PATH permit ^35121$ any
router (config) # ip as-path access-list NEIGHBOR_PATH deny .* any

Step 2: Configure the route-map and match the as-path access-list.

route-map TrafficOtherAS_Path permit 10
 match as-path NEIGHBOR_PATH

Step 3: Apply the route-map to the appropriate neighbor.

router (config) # router bgp 65000
router (config-router-bgp) #neighbor 10.1.12.2 route-map TrafficOtherAS_Path in'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59672r882328_chk'
  tag severity: 'low'
  tag gid: 'V-255996'
  tag rid: 'SV-255996r882330_rule'
  tag stig_id: 'ARST-RT-000100'
  tag gtitle: 'SRG-NET-000018-RTR-000010'
  tag fix_id: 'F-59615r882329_fix'
  tag 'documentable'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
