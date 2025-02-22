control 'SV-217056' do
  title 'The Juniper BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).'
  desc 'Advertisement of routes by an autonomous system for networks that do not belong to any of its customers pulls traffic away from the authorized network. This causes a denial of service (DoS) on the network that allocated the block of addresses and may cause a DoS on the network that is inadvertently advertising it as the originator. It is also possible that a misconfigured or compromised router within the GIG IP core could redistribute IGP routes into BGP, thereby leaking internal routes.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.” 

Review the router configuration to verify that there is a filter defined to only advertise routes for prefixes that belong to any customers or the local AS. 

Verify that a policy has been configured to filter prefixes for BGP advertisement as shown in the example below.

}
policy-options {
    …
    …
    …
    policy-statement BGP_ADVERTISE_POLICY {
        term INCLUDE_LOCAL {
            from {
                prefix-list OUR_PREFIXES;
            }
            then accept;
        }
        term INCLUDE_CUST1 {
            from {
                prefix-list CUST1_PREFIXES;
            }
            then accept;
        }
        term INCLUDE_CUST2 {
            from {
                prefix-list CUST2_PREFIXES;
            }
            then accept;
        }
        term REJECT_OTHER {
            then reject;
        }
    }

Verify that the export statement as shown below references the advertise policy. 

protocols {
    bgp {
        group AS4 {
            type external;
            import FILTER_ROUTES;
            export BGP_ADVERTISE_POLICY;
            peer-as 4;
            neighbor x.x.x.x;
        }
        group CUST1 {
            type external;
            import FILTER_CUST1_ROUTES;
            export BGP_ADVERTISE_POLICY;
            peer-as 55;
            neighbor x.x.x.x;
            neighbor x.x.x.x;
        }
        group CUST2 {
            type external;
            import FILTER_CUST2_ROUTES;
            export BGP_ADVERTISE_POLICY;
            peer-as 44;
            neighbor x.x.x.x;
            neighbor x.x.x.x;
        }
    }
    …
    …
    …
}

Note: The prefix lists should have already been configured per the previous requirements.

If the router is not configured to reject outbound route advertisements that do not belong to any customers or the local AS, this is a finding.'
  desc 'fix', 'Configure the router to filter outbound route advertisements for prefixes that are not allocated to or belong to any customer or the local autonomous system.

Configure a policy-statement to filter BGP route advertisements that will only include the local and customer prefixes.

[edit policy-options]
set policy-statement BGP_ADVERTISE_POLICY term INCLUDE_LOCAL from prefix-list OUR_PREFIXES
set policy-statement BGP_ADVERTISE_POLICY term INCLUDE_LOCAL then accept
set policy-statement BGP_ADVERTISE_POLICY term INCLUDE_CUST1 from prefix-list CUST1_PREFIXES
set policy-statement BGP_ADVERTISE_POLICY term INCLUDE_CUST1 then accept 
set policy-statement BGP_ADVERTISE_POLICY term INCLUDE_CUST2 from prefix-list CUST2_PREFIXES
set policy-statement BGP_ADVERTISE_POLICY term INCLUDE_CUST2 then accept 
set policy-statement BGP_ADVERTISE_POLICY term REJECT_OTHER then reject

Note: The prefix lists should have already been configured per the previous requirements.

Configure an export statement referencing the advertise policy on all external BGP peer groups as shown in the example below.

[edit protocols bgp group GROUP_AS4]
set export BGP_ADVERTISE_POLICY 
[edit protocols bgp group CUST1]
set export BGP_ADVERTISE_POLICY 
[edit protocols bgp group CUST2]
set export BGP_ADVERTISE_POLICY'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18285r297036_chk'
  tag severity: 'medium'
  tag gid: 'V-217056'
  tag rid: 'SV-217056r604135_rule'
  tag stig_id: 'JUNI-RT-000510'
  tag gtitle: 'SRG-NET-000018-RTR-000005'
  tag fix_id: 'F-18283r297037_fix'
  tag 'documentable'
  tag legacy: ['SV-101107', 'V-90897']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
