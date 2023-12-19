control 'SV-207106' do
  title 'The BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  desc 'Verifying the path a route has traversed will ensure that the local AS is not used as a transit network for unauthorized traffic. To ensure that the local AS does not carry any prefixes that do not belong to any customers, all PE routers must be configured to reject routes with an originating AS other than that belonging to the customer.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify the router is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Step 1: Review router configuration and verify that there is an as-path access-list statement defined to only accept routes from a CE router whose AS did not originate the route. 

Step 2: Verify that the as-path access list is referenced by the filter-list inbound for the appropriate BGP neighbors.

If the router is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, this is a finding.'
  desc 'fix', 'Configure the router to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7367r382163_chk'
  tag severity: 'low'
  tag gid: 'V-207106'
  tag rid: 'SV-207106r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000010'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7367r382164_fix'
  tag 'documentable'
  tag legacy: ['V-92243', 'SV-102345']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
