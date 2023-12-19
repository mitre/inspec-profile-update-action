control 'SV-217057' do
  title 'The Juniper BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.'
  desc 'Outbound route advertisements belonging to the core can result in traffic either looping or being black holed, or at a minimum, using a non-optimized path.'
  desc 'check', 'Review the router configuration to verify that there is a filter defined to block route advertisements for prefixes that belong to the IP core. 

Verify a prefix list has been configured containing prefixes belonging to the local autonomous system as shown in the example below.

policy-options {
    …
    …
    …
    prefix-list CORE_PREFIX {
        x.x.x.x/16;
    }

Verify that a policy has been configured to not advertise prefixes belong to the core as shown in the example below.

policy-options {
    …
    …
    …
    policy-statement BGP_ADVERTISE_POLICY {
        term EXCLUDE_CORE {
            from {
                prefix-list CORE_PREFIX;
            }
            then reject;
        }
                term INCLUDE_OTHER {
            then accept;
        }
    }

Verify that the export statement as shown below references the advertise policy. 

protocols {
    bgp {
        group AS4 {
            type external;
            export BGP_ADVERTISE_POLICY;
            peer-as 4;
            neighbor x.x.x.x;
        }

If the router is not configured to reject outbound route advertisements that belong to the IP core, this is a finding.'
  desc 'fix', 'Configure the router to filter outbound route advertisements belonging to the IP core.

Configure a prefix list containing prefixes belonging to the IP core.

[edit policy-options]
set prefix-list CORE_PREFIX x.x.x.x/16

Configure a policy-statement to filter BGP route advertisements that will exclude core prefixes.

[edit policy-options]
set policy-statement BGP_ADVERTISE_POLICY term EXCLUDE_CORE from prefix-list CORE_PREFIX
set policy-statement BGP_ADVERTISE_POLICY term EXCLUDE_CORE then reject
set policy-statement BGP_ADVERTISE_POLICY term INCLUDE_OTHER then accept

Configure an export statement referencing the advertise policy on all external BGP peer groups as shown in the example below.

[edit protocols bgp group GROUP_AS4]
set export BGP_ADVERTISE_POLICY'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18286r297039_chk'
  tag severity: 'medium'
  tag gid: 'V-217057'
  tag rid: 'SV-217057r639663_rule'
  tag stig_id: 'JUNI-RT-000520'
  tag gtitle: 'SRG-NET-000205-RTR-000006'
  tag fix_id: 'F-18284r297040_fix'
  tag 'documentable'
  tag legacy: ['V-90899', 'SV-101109']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
