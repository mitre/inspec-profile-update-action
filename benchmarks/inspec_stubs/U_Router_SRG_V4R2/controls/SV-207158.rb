control 'SV-207158' do
  title 'The PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'IGMP snooping provides a way to constrain multicast traffic at Layer 2. By monitoring the IGMP membership reports sent by hosts within the bridge domain, the snooping application can set up Layer 2 multicast forwarding tables to deliver traffic only to ports with at least one interested member within the VPLS bridge, thereby significantly reducing the volume of multicast traffic that would otherwise flood an entire VPLS bridge domain. The IGMP snooping operation applies to both access circuits and pseudowires within a VPLS bridge domain.'
  desc 'check', 'Review the router configuration to verify that IGMP or MLD snooping has been configured for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain (VFI instance).

If the router is not configured to implement IGMP or MLD snooping for each VPLS bridge domain, this is a finding.'
  desc 'fix', 'Configure IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7419r382502_chk'
  tag severity: 'low'
  tag gid: 'V-207158'
  tag rid: 'SV-207158r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000119'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7419r382503_fix'
  tag 'documentable'
  tag legacy: ['V-78309', 'SV-93015']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
