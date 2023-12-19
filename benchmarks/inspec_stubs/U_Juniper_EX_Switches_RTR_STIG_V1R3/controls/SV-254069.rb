control 'SV-254069' do
  title 'The Juniper PE router must be configured to enforce the split-horizon rule for all pseudowires within a Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'A virtual forwarding instance (VFI) must be created on each participating PE router for each customer VLAN using VPLS for carrier Ethernet services. The VFI specifies the VPN ID of a VPLS domain, the addresses of other PE routers in the domain, and the type of tunnel signaling and encapsulation mechanism for each peer PE router. The set of VFIs formed by the interconnection of the emulated VCs is called a VPLS instance, which forms the logic bridge over the MPLS core network.

The PE routers use the VFI with a unique VPN ID to establish a full mesh of emulated virtual circuits or pseudowires to all the other PE routers in the VPLS instance. The full-mesh configuration allows the PE router to maintain a single broadcast domain. With a full-mesh configuration, signaling and packet replication requirements for each provisioned virtual circuit on a PE can be high. To avoid the problem of a packet looping in the provider core, thereby adding more overhead, the PE devices must enforce a split-horizon principle for the emulated virtual circuits; that is, if a packet is received on an emulated virtual circuit, it is not forwarded on any other virtual circuit.'
  desc 'check', 'Review the PE router configuration to verify that split horizon is enabled. By default, Juniper devices configured as PE routers and VPLS enforce split horizon operation. Except for H-VPLS, Juniper devices do not support disabling split horizon operation.

LDP signaled VPLS requires a full mesh topology, which can lead to scaling issues. Hierarchical VPLS (H-VPLS) partitions the VPLS domains into mesh groups, reducing the required number of pseudo wires. However, the inner VPLS domain may require split horizon be disabled. Juniper devices support these scenarios with the "local-switching" command. Ensure mesh groups supporting H-VPLS do not have the "local-switching" directive enabled, unless required, as shown in the following example. Generally, only inner mesh groups (that is, a group "nested" within another) may require split horizon be disabled.

[edit routing-instances <name> protocols vpls]
mesh-group <name> {
    :
    local-switching;
    :
}

Note: Only EX9200-series devices currently support VPLS.

If split horizon is disabled but not required to be, this is a finding.

Note: In a ring VPLS, split horizon is disabled so that a PE router can forward a packet received from one pseudowire to another pseudowire. To prevent the consequential loop, at least one span in the ring would not have a pseudowire for any given VPLS instance.'
  desc 'fix', 'Enable split horizon on all PE routers deploying VPLS in a full-mesh configuration.
There is no fix for full mesh VPLS because Juniper PE devices with VPLS do not support or require a CLI command to enable/disabled split horizon. Split horizon operation cannot be disabled.

For H-VPLS, delete the "local-switching" directive for all inner mesh groups that do not require split horizon be disabled.
delete routing-instances <name> protocols vpls mesh-group <name> local-switching'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57521r844238_chk'
  tag severity: 'low'
  tag gid: 'V-254069'
  tag rid: 'SV-254069r844240_rule'
  tag stig_id: 'JUEX-RT-000970'
  tag gtitle: 'SRG-NET-000512-RTR-000010'
  tag fix_id: 'F-57472r844239_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
