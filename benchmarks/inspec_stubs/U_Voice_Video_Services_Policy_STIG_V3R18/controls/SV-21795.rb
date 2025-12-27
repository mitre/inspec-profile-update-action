control 'SV-21795' do
  title 'The 802.1x authentication server must place voice video traffic in the correct VLAN when authorizing LAN access for voice video endpoints.'
  desc '802.1x has the capability of configuring the network access switch port to assign a VLAN or apply filtering rules based upon the device that was just authenticated. This is done via the “success” message sent from the authentication server back to the authenticator. General VVoIP and video conferencing requirements dictate that traffic from these devices is to be separated from the general LAN traffic and workstations by VLAN and IP address separation or segregation. An implementation of 802.1x within the LAN must support this requirement. As such, the authentication server must provide the LAN switch with the proper VLAN configuration depending upon the device that is authenticated. 

For example, if all LAN ports are configured to use 802.1x LAN access control, and (as the typical case would be) are configured as disabled until a device authenticates, each port must support the authentication of a general workstation (a data device) or voice video endpoints. 

If a workstation authenticates, the switch port must be configured with the data VLAN. If a VVoIP endpoint authenticates, the switch port must be configured with the VVoIP VLAN. Video conference endpoints must be similarly configured. 

If a VVoIP endpoint that contains a PC port authenticates, the switch port must be configured with the VVoIP VLAN to receive the VVoIP traffic AND must be configured with the data VLAN to receive traffic from the PC port. Alternately, the switch port must be preconfigured for whatever device is expected to connect while in standby and implement the configuration when activated. The latter, however, is not how this is typically configured.'
  desc 'check', 'Review site documentation to confirm the 802.1x authentication server places voice video traffic in the correct VLAN when authorizing LAN access for voice video endpoints. When the network access control implementation uses 802.1x and the network access switch ports are configured as 802.1x authenticators, ensure the voice video endpoints integrate into the 802.1x access control system.

If the 802.1x authentication server does not place data and voice video traffic in the correct VLANs when authorizing LAN access for voice video endpoints, this is a finding.

An example follows: 
If all LAN ports are configured to use 802.1x LAN access control (as the typical case would be), and are configured as disabled until a device authenticates, each port must support the authentication of a general workstation (a data device) or voice video endpoints. 

If a workstation authenticates, the switch port must be configured with the data VLAN. If a VVoIP endpoint authenticates, the switch port must be configured with the VVoIP VLAN. If a video conference endpoint authenticates, the switch port must be configured with the video conference VLAN. When a VVoIP endpoint that contains a PC port authenticates, the switch port must be configured with the VVoIP VLAN to receive the VVoIP traffic AND must be configured with the data VLAN to receive traffic from the PC port.

When a voice video endpoint provides a PC port, and the PC port is disabled (as required) because the 802.1x implementation cannot control LAN access via the PC port once the endpoint is authorized, the required configuration for the network access switch ports is to configure the appropriate VLAN for the voice video traffic (as required) as well as configuring the “unused” VLAN for the disabled PC port (as required).'
  desc 'fix', 'Implement and document that the 802.1x authentication server places data and voice video traffic in the correct VLANs when authorizing LAN access for voice video endpoints.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-24006r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19654'
  tag rid: 'SV-21795r3_rule'
  tag stig_id: 'VVoIP 5310'
  tag gtitle: 'VVoIP 5310'
  tag fix_id: 'F-20358r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
