control 'SV-217096' do
  title 'The Juniper Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.'
  desc 'To avoid global visibility of local information, there are a number of source-group (S, G) states in a PIM-SM domain that must not be leaked to another domain, such as multicast sources with private address, administratively scoped multicast addresses, and the auto-RP groups (224.0.1.39 and 224.0.1.40).

Allowing a multicast distribution tree, local to the core, to extend beyond its boundary could enable local multicast traffic to leak into other autonomous systems and customer networks.'
  desc 'check', 'Review the router configuration to determine if there is export policy to block local source-active multicast advertisements.

Verify that the router is configured with an export policy to filter multicast source-active advertisements.

policy-options {
   …
    …
    …
    }
    policy-statement SA_EXPORT {
        term INTERNAL_GROUP {
            from {
                route-filter 239.0.0.0/8 orlonger;
            }
            then reject;
        }
        term INTERNAL_ADDR {
            from {
                source-address-filter 10.0.0.0/8 orlonger;
            }
            then reject;
        }
        term ACCEPT_OTHERS {
            then accept;
        }
    }

Verify that an export source-active filter has been applied to MSDP.

protocols {
    …
    …
    …
    }
    msdp {
       export SA_IMPORT;

If the router is not configured with an export policy to block local source-active multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the router with an export policy avoid global visibility of local multicast (S, G) states. The example below will avoid exporting multicast active sources belonging to the private network.

[edit policy-options]
set policy-statement SA_EXPORT term INTERNAL_GROUP from route-filter 239.0.0.0/8 orlonger
set policy-statement SA_EXPORT term INTERNAL_GROUP then reject
set policy-statement SA_EXPORT term INTERNAL_ADDR from source-address-filter 10.0.0.0/8 orlonger
set policy-statement SA_EXPORT term INTERNAL_ADDR then reject
set policy-statement SA_EXPORT term ACCEPT_OTHERS then accept

[edit protocols msdp]
set export SA_EXPORT'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18325r297156_chk'
  tag severity: 'low'
  tag gid: 'V-217096'
  tag rid: 'SV-217096r639663_rule'
  tag stig_id: 'JUNI-RT-000920'
  tag gtitle: 'SRG-NET-000018-RTR-000008'
  tag fix_id: 'F-18323r297157_fix'
  tag 'documentable'
  tag legacy: ['V-90975', 'SV-101185']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
