control 'SV-21768' do
  title 'Remote access VoIP must be routed to the VoIP VLAN.'
  desc 'In addition to complying with the STIGs and VPN requirements for remotely connected PCs, there is an additional requirement for Unified Capabilities (UC) soft client and UC applications using the VPN. UC soft client and UC application traffic which must interact or communicate with systems and devices in the voice VLAN/protection zone must be routed to that zone while the other data and communications traffic is routed to the data zone. This is to be accomplished without degrading the separation of these two zones, or bridging them together. This can be accomplished in a number of ways depending upon the LAN and its boundary/VPN architecture.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 

Ensure traffic from a Unified Capabilities (UC) soft client, operated in a remote access scenario and using an encrypted VPN as required, is routed to the VoIP VLAN such that the separation of the voice and data zones is not degraded while all other traffic is routed to the data zone.

Inspect network diagrams to determine if the boundary and remote access VLAN architecture properly routes VoIP traffic from the VPN to the voice VLANs while maintaining proper flow control and access between the data VLANs and the voice VLANs. If the boundary and remote access VLAN architecture does not properly route VoIP traffic from the VPN to the voice VLANs while maintaining proper flow control and access between the data VLANs and the voice VLANs, this is a finding.'
  desc 'fix', 'Ensure traffic from a Unified Capabilities (UC) soft client, operated in a remote access scenario and using an encrypted VPN as required, is routed to the VoIP VLAN such that the separation of the voice and data zones is not degraded while all other traffic is routed to the data zone.

Configure the enclave boundary and remote access VLAN architecture to properly route VoIP traffic from the VPN to the voice VLANs and maintain proper flow control and access between the data VLANs and the voice VLANs.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23920r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19627'
  tag rid: 'SV-21768r3_rule'
  tag stig_id: 'VVoIP 1800'
  tag gtitle: 'VVoIP 1800'
  tag fix_id: 'F-20331r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
