control 'SV-254039' do
  title 'The Juniper PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'IGMP snooping provides a way to constrain multicast traffic at layer 2. By monitoring the IGMP membership reports sent by hosts within the bridge domain, the snooping application can set up layer 2 multicast forwarding tables to deliver traffic only to ports with at least one interested member within the VPLS bridge, thereby significantly reducing the volume of multicast traffic that would otherwise flood an entire VPLS bridge domain. The IGMP snooping operation applies to both access circuits and pseudowires within a VPLS bridge domain.'
  desc 'check', 'Review the router configuration to verify that IGMP or MLD snooping has been configured for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain (VFI instance).

[edit routing-instances <name>]
protocols {
    igmp-snooping {
        vlan <VLAN name>;
    }
    mld-snooping {
        vlan <VLAN name>;
    }
}

Note: Only EX9200-series devices currently support VPLS.

If the router is not configured to implement IGMP or MLD snooping for each VPLS bridge domain, this is a finding.'
  desc 'fix', 'Configure IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.

set routing-instances <name> protocols igmp-snooping vlan <vlan ID>
set routing-instances <name> protocols mld-snooping vlan <vlan ID>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57491r844148_chk'
  tag severity: 'low'
  tag gid: 'V-254039'
  tag rid: 'SV-254039r844150_rule'
  tag stig_id: 'JUEX-RT-000670'
  tag gtitle: 'SRG-NET-000362-RTR-000119'
  tag fix_id: 'F-57442r844149_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
