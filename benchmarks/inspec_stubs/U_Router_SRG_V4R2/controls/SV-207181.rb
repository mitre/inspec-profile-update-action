control 'SV-207181' do
  title 'The PE router must be configured to enforce the split-horizon rule for all pseudowires within a Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'A virtual forwarding instance (VFI) must be created on each participating PE router for each customer VLAN using VPLS for carrier Ethernet services. The VFI specifies the VPN ID of a VPLS domain, the addresses of other PE routers in the domain, and the type of tunnel signaling and encapsulation mechanism for each peer PE router. The set of VFIs formed by the interconnection of the emulated VCs is called a VPLS instance, which forms the logic bridge over the MPLS core network.

The PE routers use the VFI with a unique VPN ID to establish a full mesh of emulated virtual circuits or pseudowires to all the other PE routers in the VPLS instance. The full-mesh configuration allows the PE router to maintain a single broadcast domain. With a full-mesh configuration, signaling and packet replication requirements for each provisioned virtual circuit on a PE can be high. To avoid the problem of a packet looping in the provider core, thereby adding more overhead, the PE devices must enforce a split-horizon principle for the emulated virtual circuits; that is, if a packet is received on an emulated virtual circuit, it is not forwarded on any other virtual circuit.'
  desc 'check', 'Review the PE router configuration to verify that split horizon is enabled.

If it is disabled, this is a finding.

Note: In a ring VPLS, split horizon is disabled so that a PE router can forward a packet received from one pseudowire to another pseudowire. To prevent the consequential loop, at least one span in the ring would not have a pseudowire for any given VPLS instance.'
  desc 'fix', 'Enable split horizon on all PE routers deploying VPLS in a full-mesh configuration.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7442r382631_chk'
  tag severity: 'low'
  tag gid: 'V-207181'
  tag rid: 'SV-207181r604135_rule'
  tag stig_id: 'SRG-NET-000512-RTR-000010'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7442r382632_fix'
  tag 'documentable'
  tag legacy: ['V-78305', 'SV-93011']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
