control 'SV-216693' do
  title 'The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  desc 'Verifying the path a route has traversed will ensure that the local AS is not used as a transit network for unauthorized traffic. To ensure that the local AS does not carry any prefixes that do not belong to any customers, all PE routers must be configured to reject routes with an originating AS other than that belonging to the customer.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify the router is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Step 1: Review router configuration and verify that there is an as-path access-list statement defined to only accept routes from a CE router whose AS did not originate the route. The configuration should look similar to the following:

ip as-path access-list 10 permit ^yy$
ip as-path access-list 10 deny .*

Note: the characters “^” and “$” representing the beginning and the end of the expression respectively are optional and are implicitly defined if omitted.

Step 2: Verify that the as-path access-list is referenced by the filter-list inbound for the appropriate BGP neighbors as shown in the example below:

router bgp xx
neighbor x.1.4.12 remote-as yy
neighbor x.1.4.12 filter-list 10 in

If the router is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to reject updates from CE routers with an originating AS in the AS_PATH attribute that do not belong to that customer.

Step 1: Configure the as-path ACL as shown in the example below:

R1(config)#ip as-path access-list 10 permit ^yy$
R1(config)#ip as-path access-list 10 deny .*

Step 2: Apply the as-path filter inbound as shown in the example below:

R1(config)#router bgp xx
R1(config-router)#neighbor x.1.4.12 filter-list 10 in'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17926r288024_chk'
  tag severity: 'low'
  tag gid: 'V-216693'
  tag rid: 'SV-216693r531086_rule'
  tag stig_id: 'CISC-RT-000550'
  tag gtitle: 'SRG-NET-000018-RTR-000010'
  tag fix_id: 'F-17924r288025_fix'
  tag 'documentable'
  tag legacy: ['SV-106097', 'V-96959']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
