control 'SV-216707' do
  title 'The Cisco PE router must be configured to enforce the split-horizon rule for all pseudowires within a Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'A virtual forwarding instance (VFI) must be created on each participating PE router for each customer VLAN using VPLS for carrier Ethernet services. The VFI specifies the VPN ID of a VPLS domain, the addresses of other PE routers in the domain, and the type of tunnel signaling and encapsulation mechanism for each peer PE router. The set of VFIs formed by the interconnection of the emulated VCs is called a VPLS instance, which forms the logic bridge over the MPLS core network.

The PE routers use the VFI with a unique VPN ID to establish a full mesh of emulated virtual circuits or pseudowires to all the other PE routers in the VPLS instance. The full-mesh configuration allows the PE router to maintain a single broadcast domain. With a full-mesh configuration, signaling and packet replication requirements for each provisioned virtual circuit on a PE can be high. To avoid the problem of a packet looping in the provider core, thereby adding more overhead, the PE devices must enforce a split-horizon principle for the emulated virtual circuits; that is, if a packet is received on an emulated virtual circuit, it is not forwarded on any other virtual circuit.'
  desc 'check', 'Review the PE router configuration to verify that split horizon is enabled. By default, split horizon is enabled; hence, the attribute no-split-horizon should not be seen on the neighbor command as shown in the example below:

l2 vfi VPLS_A manual 
 vpn id 110
 bridge-domain 100
 neighbor 10.3.3.3 encapsulation mpls no-split-horizon

If split horizon is not enabled, this is a finding.

Note: This requirement is only applicable to a mesh VPLS topology. VPLS solves the loop problem by using a split-horizon rule which states that member PE routers of a VPLS must forward VPLS traffic only to the local attachment circuits when they receive the traffic from the other PE routers. In a ring VPLS, split horizon must be disabled so that a PE router can forward a packet received from one pseudowire to another pseudowire. To prevent the consequential loop, at least one span in the ring would not have a pseudowire for any given VPLS instance.'
  desc 'fix', 'Enable split horizon on all PE routers deploying VPLS in a full-mesh configuration.

R1(config)#l2 vfi VPLS_A manual                                 
R1(config-vfi)#neighbor 10.3.3.3 encapsulation mpls'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17940r288066_chk'
  tag severity: 'low'
  tag gid: 'V-216707'
  tag rid: 'SV-216707r531086_rule'
  tag stig_id: 'CISC-RT-000690'
  tag gtitle: 'SRG-NET-000512-RTR-000010'
  tag fix_id: 'F-17938r288067_fix'
  tag 'documentable'
  tag legacy: ['SV-106125', 'V-96987']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
