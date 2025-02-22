control 'SV-217038' do
  title 'The Juniper perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.'
  desc 'Access lists are used to separate data traffic into that which it will route (permitted packets) and that which it will not route (denied packets). Secure configuration of routers makes use of access lists for restricting access to services on the router itself as well as for filtering traffic passing through the router. 

Inbound versus Outbound: It should be noted that some operating systems default access lists are applied to the outbound queue. The more secure solution is to apply the access list to the inbound queue for three reasons:

- The router can protect itself before damage is inflicted.
- The input port is still known and can be filtered upon.
- It is more efficient to filter packets before routing them.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that an inbound filter is configured on all external interfaces as shown in the example below.

interfaces {
     description "NIPRNet";
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter {
                    input INBOUND_FILTER;
                }
                address x.x.x.x/24;
            }
        }
    }

If the router is not configured to filter traffic entering the network at all external interfaces in an inbound direction, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to use an inbound filter on all external interfaces as shown in the example below.

[edit interfaces ge-0/0/0 unit 0 family inet]
set filter input INBOUND_FILTER'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18267r296982_chk'
  tag severity: 'medium'
  tag gid: 'V-217038'
  tag rid: 'SV-217038r604135_rule'
  tag stig_id: 'JUNI-RT-000330'
  tag gtitle: 'SRG-NET-000205-RTR-000004'
  tag fix_id: 'F-18265r296983_fix'
  tag 'documentable'
  tag legacy: ['SV-101071', 'V-90861']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
