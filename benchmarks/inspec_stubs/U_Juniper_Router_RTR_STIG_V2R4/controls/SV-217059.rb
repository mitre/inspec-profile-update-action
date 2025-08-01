control 'SV-217059' do
  title 'The Juniper BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  desc 'Verifying the path a route has traversed will ensure that the local AS is not used as a transit network for unauthorized traffic. To ensure that the local AS does not carry any prefixes that do not belong to any customers, all PE routers must be configured to reject routes with an originating AS other than that belonging to the customer.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.” 

Review the router configuration to verify the router is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Step 1: Verify a policy has been configured to filter AS_PATH attribute for received BGP advertisements as shown in the example below:

policy-options {
    …
    …
    …
    policy-statement FILTER_ASx {
        term ALLOW_ASx {
            from as-path PEER_ASx;
            then accept;
        }
        term ELSE_REJECT {
            then reject;
        }
    }
    …
    …
    …
    as-path PEER_ASx "^x$";
}

Note: the characters “^” and “$” representing the beginning and the end of the expression respectively are optional and are implicitly defined if omitted.
Step 2: Verify that the import policy has been applied to all external BGP peers as shown in the example below:

protocols {
    bgp {
        group GROUP_ASx {
            type external;
            import [ FILTER_ASx FILTER_ROUTES ];
            peer-as x;
            neighbor x.x.x.x;
        }
 
If the router is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, this is a finding.'
  desc 'fix', 'Step 1: Configure a policy to filter the AS_PATH as shown in the example below: 

[edit policy-options] 
set as-path PEER_ASx "^x$" 
set policy-statement FILTER_ASx term ALLOW_ASx from as-path PEER_ASx 
set policy-statement FILTER_ASx term ALLOW_ASx then accept 
set policy-statement FILTER_ASx term ELSE_REJECT then reject 

Step 2: Apply the import policy as shown in the example below: 

[edit protocols bgp group GROUP_ASx] 
set import [FILTER_AS4 FILTER_ROUTES]'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18288r297045_chk'
  tag severity: 'low'
  tag gid: 'V-217059'
  tag rid: 'SV-217059r604135_rule'
  tag stig_id: 'JUNI-RT-000535'
  tag gtitle: 'SRG-NET-000018-RTR-000010'
  tag fix_id: 'F-18286r297046_fix'
  tag 'documentable'
  tag legacy: ['SV-105143', 'V-96005']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
