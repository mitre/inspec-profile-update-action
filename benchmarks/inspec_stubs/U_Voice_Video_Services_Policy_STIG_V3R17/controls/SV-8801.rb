control 'SV-8801' do
  title 'A hardware based VVoIP or VTC endpoint possesses or provides a “PC Port” but does not maintain the required VLAN separation through the implementation of an Ethernet switch (not a hub).'
  desc 'Some VVoIP hardware endpoints and hardware based VTC endpoints have a second Ethernet port on the device to provide a connection to external devices such as a. This port is typically called a “PC Port”. This is done so that a can share a single network cable drop and LAN access switchport. The PC port can, in general, support any device requiring an Ethernet connection. In theory, a VoIP phone, a desktop VTC unit, and a workstation could be daisy chained on a single LAN drop. These PC ports are supported by an embedded three port Ethernet switch or a hub. Hubs cannot support VLANs and therefore cannot be used to daisy chain VVoIP endpoints and non VVoIP devices in DoD networks. A switch must be used because the VVoIP or VTC endpoint must be capable of maintaining the separation of the voice (VVoIP), data, VLANs as well as the VTC VLAN and PC Comm Client VLAN if present. For example the attached PC must not be able to directly access the phone’s or VTU’s configurations or communications traffic. VAN separation helps to prevent this. NOTE: the switch or endpoint will typically utilize 802.1Q trunking (VLAN tagging) but may use some other means to separate voice and data traffic. Typically when 802.1Q VLAN tagging is used, the phone firmware tags the VoIP packets while the embedded switch passes all packets without modification. This permits devices connected to the PC port to tag their packets and assign the proper VLAN to their traffic type. 802.1Q VLAN tagging enables the LAN to better maintain separation of the traffic and is therefore the preferred method.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

Ensure a VVoIP or VTC hardware endpoint possessing a “PC Port” is capable of maintaining voice/data VLAN separation via the use of an Ethernet switch and that it does not contain an Ethernet hub OR ensure the “PC Port” is physically disabled. 

Review VVoIP or VTC hardware endpoint specifications and documentation.

This is a finding in the event the VVoIP or VTC hardware endpoint that provides PC port but cannot maintain voice/data VLAN separation.'
  desc 'fix', 'Ensure a VVoIP or VTC hardware endpoint possessing a “PC Port” contains an Ethernet switch such that VLAN separation can be maintained and that it does not contain an Ethernet hub OR ensure the “PC Port” is physically disabled.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-8306'
  tag rid: 'SV-8801r1_rule'
  tag stig_id: 'VVoIP 5700 (LAN)'
  tag gtitle: 'Deficient design: EI “PC port”  switch VLAN suppt'
  tag fix_id: 'F-20257r1_fix'
  tag 'documentable'
  tag mitigations: 'VVoIP 5700'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Denial of Service and/or unauthorized access to network or voice system resources or services and the information they contain. Loss of confidentiality. Degradation of the data and VoIP network segregation and associated problems.'
  tag mitigation_control: 'Physically disable or incapacitate the PC port so that it cannot be activated and used.'
  tag responsibility: 'Information Assurance Officer'
end
