control 'SV-253963' do
  title 'The Juniper EX switch must be configured to enable IGMP or MLD Snooping on all VLANs.'
  desc 'IGMP and MLD snooping provides a way to constrain multicast traffic at layer 2. By monitoring the IGMP or MLD membership reports sent by hosts within a VLAN, the snooping application can set up layer 2 multicast forwarding tables to deliver specific multicast traffic only to interfaces connected to hosts interested in receiving the traffic, thereby significantly reducing the volume of multicast traffic that would otherwise flood the VLAN.'
  desc 'check', 'Review the switch configuration to verify that IGMP or MLD snooping has been configured for IPv4 and IPv6 multicast traffic respectively.

Verify IGMP and MLD is globally configured for all VLANs:
[edit protocols]
igmp-snooping {
    vlan all {
        immediate-leave;
        interface <multicast router interface name>.<logical unit> {
            multicast-router-interface;
        }
    }
}
mld-snooping {
    vlan all {
        immediate-leave;
        interface <multicast router interface name>.<logical unit> {
            multicast-router-interface;
        }
    }
}

For VLAN-specific values, verify IGMP and MLD snooping is configured for each VLAN:
[edit protocols]
igmp-snooping {
    vlan vlan-name {
        immediate-leave;
        interface <multicast router interface name>.<logical unit> {
            multicast-router-interface;
        }
        interface <host interface name>.<logical unit> {
            host-only-interface;
        }
    }
}
mld-snooping {
    vlan vlan-name {
        immediate-leave;                
        interface <multicast router interface name>.<logical unit> {
            multicast-router-interface;
        }
        interface <host interface name>.<logical unit> {
            host-only-interface;
        }
    }
}

If the switch is not configured to implement IGMP or MLD snooping for each VLAN, this is a finding.'
  desc 'fix', 'Configure IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VLAN.

Global:
set protocols igmp-snooping vlan all immediate-leave
set protocols igmp-snooping vlan all interface <multicast router interface name>.<logical unit> multicast-router-interface
set protocols mld-snooping vlan all immediate-leave
set protocols mld-snooping vlan all interface <multicast router interface name>.<logical unit> multicast-router-interface

Per VLAN:
set protocols igmp-snooping vlan vlan-name immediate-leave
set protocols igmp-snooping vlan vlan-name interface <multicast router interface name>.<logical unit> multicast-router-interface
set protocols igmp-snooping vlan vlan-name interface <host interface name>.<logical unit> host-only-interface
set protocols mld-snooping vlan vlan-name immediate-leave
set protocols mld-snooping vlan vlan-name interface <multicast router interface name>.<logical unit> multicast-router-interface
set protocols mld-snooping vlan vlan-name interface <host interface name>.<logical unit> host-only-interface'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57415r843920_chk'
  tag severity: 'low'
  tag gid: 'V-253963'
  tag rid: 'SV-253963r843922_rule'
  tag stig_id: 'JUEX-L2-000160'
  tag gtitle: 'SRG-NET-000512-L2S-000002'
  tag fix_id: 'F-57366r843921_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
