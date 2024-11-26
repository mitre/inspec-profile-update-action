control 'SV-217061' do
  title 'The Juniper BGP router must be configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer.'
  desc 'The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if it is compliant with this requirement.

Verify that a policy statement has been configured to reject prefixes longer than /24 or the least significant prefixes issued to the customers as shown in the example below.

policy-options {
    …
    …
    …
    }
    policy-statement NO_LONG_PREFIXES {
        from {
            route-filter 0.0.0.0/0 prefix-length-range /25-/32 reject;
        }
    }

Note: It may be necessary to configure separate policy statements depending on the address space issued to each customer.

Verify that there is an import statement referencing the policy statement to filter prefix length.

protocols {
    bgp {
        …
        …
        …
        }
        group CUST1 {
            type external;
            import [ FILTER_CUST1_ROUTES NO_LONG_PREFIXES ];
            peer-as 55;
            neighbor x.x.x.x;
            neighbor x.x.x.x;
        }
        group CUST2 {
            type external;
            import [ FILTER_CUST1_ROUTES NO_LONG_PREFIXES ];
            peer-as 44;
            neighbor x.x.x.x;
            neighbor x.x.x.x;
        }

If the router is not configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer, this is a finding.'
  desc 'fix', 'Configure the router to limit the prefix size on any route advertisement to /24 or the least significant prefixes issued to the customer.

Configure a route filter to reject any prefix that is longer than /24.

[edit policy-options]
set policy-statement NO_LONG_PREFIXES from route-filter 0.0.0.0/0 prefix-length-range /25-/32 reject

Apply the policy statement to the BGP customer groups.

[edit protocols bgp group CUST1]
set import NO_LONG_PREFIXES
[edit protocols bgp group CUST2]
set import NO_LONG_PREFIXES'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18290r297051_chk'
  tag severity: 'low'
  tag gid: 'V-217061'
  tag rid: 'SV-217061r639663_rule'
  tag stig_id: 'JUNI-RT-000550'
  tag gtitle: 'SRG-NET-000362-RTR-000118'
  tag fix_id: 'F-18288r297052_fix'
  tag 'documentable'
  tag legacy: ['V-90905', 'SV-101115']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
