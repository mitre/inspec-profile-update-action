control 'SV-21773' do
  title 'Logical or physical interfaces must be configured on the VVoIP core routing devices for the VVoIP core equipment to support access and traffic control for the VVoIP system components.'
  desc 'VLAN and IP address segmentation enables access and traffic control for the VVoIP system components. Only the required protocols are to reach a given VVoIP device thereby protecting it from non-essential protocols. This protection is afforded on the LAN by implementing ACLs based on VLAN/subnet, protocol and in some instances specific IP addresses. While a firewall placed between the core equipment and endpoint VLANs might provide better protection for the core equipment as a whole, a router is best suited to control the varying traffic patterns between the various devices.'
  desc 'check', 'Inspect the configurations of the VVoIP core routing devices to determine compliance with the following requirement:

Ensure logical or physical interfaces (VLAN/subnets or direct connect physical interfaces with discrete subnets) are configured on the VVoIP core routing devices for the VVoIP core equipment as follows: 
- VVoIP system core control equipment containing the LSC, endpoint configuration server, and DHCP server if used, etc.
- VVoIP system management VLAN which is separate from the general LAN management VLAN.
- Media gateways to the DSN and PSTN.
- Signaling gateways (SG) to the DSN.
- DoD WAN access VVoIP firewall (SBC or other).
- Voicemail and Unified Messaging Servers, which may need to be accessible from both the voice and data VLANs.
- UC servers supporting presence, web browser based conferencing, and directory services. These may need to be accessible from both the voice and data VLANs.
Alternately, ensure the VVoIP core equipment employs direct connections with discrete subnets to the VVoIP core routing devices so that the ACLs may be implemented on the physical interface to the device instead of the logical interface to the VLAN.
NOTE: If the device for which a VLAN/subnet is designated does not exist in the system, the VLAN is not required. These devices may be the core routing devices for the data LAN as well.

If the logical or physical interfaces with discrete subnets have not been implemented against which the ACLs can be applied, this is a finding.'
  desc 'fix', 'Ensure logical or physical interfaces (VLAN/subnets or direct connect physical interfaces with discrete subnets) are established/configured on the VVoIP core routing devices for the VVoIP core equipment as follows: 
- VVoIP system core control equipment containing the LSC, endpoint configuration server, and DHCP server if used, etc. 
- VVoIP system management VLAN which is separate from the general LAN management VLAN.
- Media gateways to the DSN and PSTN.
- Signaling gateways (SG) to the DSN.
- DoD WAN access VVoIP firewall (SBC or other).
- Voicemail and Unified Messaging Servers, which may need to be accessible from both the voice and data VLANs.
- UC servers supporting presence, web browser based conferencing, and directory services. These may need to be accessible from both the voice and data VLANs.
Alternately, ensure the VVoIP core equipment employs direct connections with discrete subnets to the VVoIP core routing devices so that the ACLs may be implemented on the physical interface to the device instead of the logical interface to the VLAN.
NOTE: If the device for which a VLAN/subnet is designated does not exist in the system, the VLAN is not required. These devices may be the core routing devices for the data LAN as well.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23958r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19632'
  tag rid: 'SV-21773r3_rule'
  tag stig_id: 'VVoIP 5520'
  tag gtitle: 'VVoIP 5520'
  tag fix_id: 'F-20336r2_fix'
  tag 'documentable'
end
