control 'SV-21770' do
  title 'VVoIP core components must use DHCP static allocation (reservations) or be statically addressed.'
  desc 'Assigning static addresses to core VVoIP servers and devices permits tighter control using ACLs on firewalls and routers to help in the protection of these devices.'
  desc 'check', 'Review VVoIP network design to determine how the VVoIP core components IP address is set or configured.

Ensure the VVoIP core components use static addressing.

If all VVoIP core components are not statically addressed, by either direct configuration or using DHCP static allocation, this is a finding.'
  desc 'fix', 'Configure all VVoIP core components to use static addressing. The VVoIP core components may be statically addressed by either direct configuration or using DHCP static allocation.

When DHCP static allocation is used, configure the DHCP server supporting VVoIP core components to use a unique DHCP scope separate from other voice, video, data, and management scopes.

Ensure the DHCP server and associated network routing prevents traffic to flow between the VVoIP core component network segment, or VLAN, and any other network segments or VLANs.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23952r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19629'
  tag rid: 'SV-21770r3_rule'
  tag stig_id: 'VVoIP 5230'
  tag gtitle: 'VVoIP 5230'
  tag fix_id: 'F-20333r2_fix'
  tag 'documentable'
end
