control 'SV-21790' do
  title 'LAN access switchport supporting a VVoIP or VTC endpoint that does not, or is not configured to, apply 802.1Q VLAN tags to its traffic is NOT statically assigned to the appropriate local VVoIP or VTC VLAN.'
  desc 'VVoIP or VTC endpoints that are not configured to or cannot provide a 802.1Q VLAN tag to its VVoIP traffic have no control over what VLAN their traffic ends up in, if any. Therefore the responsibility of placing VVoIP or VTC traffic in an appropriate VLAN for the type of traffic falls to the LAN switch. As such each switchport on a LAN NE that supports a VVoIP or VTC endpoint must place the traffic in the correct VLAN. This means that, in lieu of any other means to sort the traffic, each switchport must be statically assigned to the appropriate VLAN. 

NOTE: In some cases a LAN NE can use some other endpoint or traffic characteristic other than 802.1Q tagging to assign the traffic to the correct VLAN.'
  desc 'check', 'Inspect LAN access switchport configuration settings to confirm compliance with the following requirement:
In the event a VVoIP or VTC endpoint does not, or is not configured to, apply 802.1Q VLAN tags to its VVoIP or VTC traffic, ensure the supporting LAN access switchport is statically assigned to the appropriate local VVoIP or VTC VLAN.

This is not a finding in the event the LAN NE is configured to place the VVoIP or VTC traffic in the correct VLAN by some other method (e.g., MAC based).  

This is a finding in the event static VLAN assignment of the LAN access switchport is not configured to place the VVoIP VTC traffic in the correct VLAN in lieu of another method being configured.

NOTE: While some LAN NEs have the capability of sorting traffic into VLANs based upon the protocol type, this method does not meet the intent of this requirement (i.e., the separation of VVoIP or VTC traffic to limit access to it and protect the system) since a PC could use similar protocols to those used by VVoIP or VTC endpoints for applications that are not associated with the VVoIP or VTC system which should therefore be kept separate. Using this method, the separation and resulting protection of the VVoIP or VTC system is diminished and a malicious user might be capable of using this to compromise the system.'
  desc 'fix', 'In the event the VVoIP or VTC endpoint does not, or is not configured to, apply 802.1Q VLAN tags to its VVoIP traffic; and the switchport is not configured to place the VVoIP or VTC traffic in the correct VLAN by some other method (other than by protocol type) ensure the supporting LAN access switchport is statically assigned to the appropriate local VVoIP or VTC VLAN.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23998r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19649'
  tag rid: 'SV-21790r2_rule'
  tag stig_id: 'VVoIP 5550'
  tag gtitle: 'Deficient LAN switch port config: static VLAN Assn'
  tag fix_id: 'F-20353r1_fix'
  tag 'documentable'
end
