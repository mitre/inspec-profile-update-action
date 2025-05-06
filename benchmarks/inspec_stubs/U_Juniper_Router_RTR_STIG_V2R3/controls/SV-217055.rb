control 'SV-217055' do
  title 'The Juniper BGP router must be configured to reject inbound route advertisements from a customer edge (CE) Juniper router for prefixes that are not allocated to that customer.'
  desc 'As a best practice, a service provider should only accept customer prefixes that have been assigned to that customer and any peering autonomous systems. A multi-homed customer with BGP speaking routers connected to the Internet or other external networks could be breached and used to launch a prefix de-aggregation attack. Without ingress route filtering of customers, the effectiveness of such an attack could impact the entire IP core and its customers.'
  desc 'check', 'Review the router configuration to verify that there are filters defined to only accept routes for prefixes that belong to specific customers. 

Verify prefix list has been configured containing prefixes belonging to each customer as shown in the example below.

policy-options {
    …
    …
    …
    prefix-list CUST1_PREFIXES {
        x.x.x.x/24;
        x.x.x.x/24;
    }
    prefix-list CUST2_PREFIXES {
        x.x.x.x/24;
    }

Verify that a policy has been configured to only accept routes belonging to the customer.

policy-options {
    …
    …
    …
    policy-statement FILTER_CUST1_ROUTES {
        term ACCEPT-ROUTES {
            from {
                prefix-list CUST1_PREFIXES;
            }
            then accept;
        }
        term REJECT_OTHER {
            then reject;
        }
    }
    policy-statement FILTER_CUST2_ROUTES {
        term ACCEPT_ROUTES {
            from {
                prefix-list CUST2_PREFIXES;
            }
            then accept;
        }
        term REJECT_OTHER {
            then reject;
        }
    }
}

Verify that the configured policy to filter customer prefixes has been applied to customer BGP peers as shown in the example below.

protocols {
    bgp {
        …
        …
        …
        }
        group CUST1 {
            type external;
            import FILTER_CUST1_ROUTES;
            peer-as 55;
            neighbor x.x.x.x;
            neighbor x.x.x.x;
        }
        group CUST2 {
            type external;
            import FILTER_CUST2_ROUTES;
            peer-as 44;
            neighbor x.x.x.x;
            neighbor x.x.x.x;
        }
    }
    …
    …
    …
}

Note: Routes to PE-CE links within a VPN are needed for troubleshooting end-to-end connectivity across the MPLS/IP backbone. Hence, these prefixes are an exception to this requirement.

If the router is not configured to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer, this is a finding.'
  desc 'fix', 'Configure the router to reject inbound route advertisements from a CE router for prefixes that are not allocated to that customer.

Configure a prefix list containing prefixes belonging to the customers.

[edit policy-options]
set prefix-list CUST1_PREFIXES x.x.x.x/24
set prefix-list CUST1_PREFIXES x.x.x.x/24
set prefix-list CUST2_PREFIXES x.x.x.x/24
set prefix-list CUST2_PREFIXES x.x.x.x/24

Configure a policy-statement to filter customer routes.

set policy-statement FILTER_CUST1_ROUTES term ACCEPT_ROUTES from prefix-list CUST1_PREFIXES
set policy-statement FILTER_CUST1_ROUTES term then accept
set policy-statement FILTER_CUST1_ROUTES term REJECT_OTHER then reject
set policy-statement FILTER_CUST2_ROUTES term ACCEPT_ROUTES from prefix-list CUST2_PREFIXES
set policy-statement FILTER_CUST2_ROUTES term then accept
set policy-statement FILTER_CUST2_ROUTES term REJECT_OTHER then reject

Apply the import policy to filter received routes for each customer group.

[edit protocols bgp group CUST1]
set import FILTER_CUST1_ROUTES 
[edit protocols bgp group CUST2]
set import FILTER_CUST2_ROUTES'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18284r297033_chk'
  tag severity: 'medium'
  tag gid: 'V-217055'
  tag rid: 'SV-217055r604135_rule'
  tag stig_id: 'JUNI-RT-000500'
  tag gtitle: 'SRG-NET-000018-RTR-000004'
  tag fix_id: 'F-18282r297034_fix'
  tag 'documentable'
  tag legacy: ['SV-101105', 'V-90895']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
