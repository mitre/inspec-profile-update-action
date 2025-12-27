control 'SV-23735' do
  title 'The VVoIP system time is not properly implemented and/or synched with the LAN’s NTP servers.'
  desc 'It is critical that the network time be synchronized across all network elements when troubleshooting network problems or investigating an incident. Each log entry is required to be time stamped. If time-stamps are not synchronised, it can be difficult or impossible to see in what order events occurred. Additionally legacy telecommunications systems require synchronized time. Network elements (NE). 

The Network Infrastructure STIG provides guidance for using NTP and implementing NTP servers within the enclave or LAN. A paraphrased summary of the basic requirements follows:
> Implement two NTP servers in the LAN management network to act as the source of NTP information to the rest of the enclave/LAN.
> Reference the two NTP servers to two different stratum 1 reference clocks via GPS or NIST WWVB.
> Harden NTP servers in accordance with the applicable OS STIG.
> Distribute NTP information to all LAN NEs via the management interface. This provides a protected environment for the distribution of network time.
> All received and sent messages between NTP peers are authenticated.
> Receive NTP messages from authorized sources based on their IP address. 
> All LAN NEs are configured to receive NTP messages from two NTP sources within the LAN such that one backs up the other. 
> Distribution of 
NOTE: This list is not complete and is provided as information only. Refer to the current Network Infrastructure STIG for all policy and requirements associated with NTP use and implementation in the LAN. 

The VVoIP system must be synchronized with the LAN time, minimally to support troubleshooting and incident response. Therefore the VVoIP system must be integrated into the LAN’S NTP system in accordance with the Network Infrastructure STIG NTP guidance. Its network time must not be synchronized with an independent source. 

Additionally, if the VVoIP system is synchronized with an independent source via the Internet, the VVoIP system becomes exposed to NTP exploits and attacks from the Internet.

Implementing NTP within the VVoIP system will require the system/call controller to be configured to receive authenticated NTP messages from the two NTP server IP addresses via its management interface. This will require that permissions be granted between the VVoIP management VLAN and the LAN management VLAN such that NTP requests and responses can flow between the VVoIP system controller and the two NTP servers in the LAN management VLAN. If the VVoIP endpoints time is synchronized via NTP, the VVoIP controller will have to serve as their NTP server since the endpoints do not have access to the VVoIP or LAN management VLANs and should not be permitted such access.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure the VVoIP system’s time is synchronized with or receives its time from the two internal LAN NTP servers that are configured within the LAN management VLAN in accordance with the Network Infrastructure STIG. Further ensure the VVoIP endpoints receive their time from the VVoIP system controller.

NOTE: The use and implementation of NTP within the VVoIP system must be implemented in accordance with the Network Infrastructure STIG NTP requirements and policies. 

This is a finding in the event these conditions are not met.

Additionally determine how the endpoints time is synchronized. This is a finding in the event their time is not sourced from the VVoIP system controller via the VVoIP VLANs.'
  desc 'fix', 'Implement NTP usage in the VVoIP system in accordance with the Network Infrastructure STIG policy and requirements. 

Ensure the VVoIP system’s time is synchronized with or receives its time from the two internal LAN NTP servers that are configured within the LAN management VLAN in accordance with the Network Infrastructure STIG. Further ensure the VVoIP endpoints receive their time from the VVoIP system controller.

NOTE: Implementing NTP within the VVoIP system will require the system/call controller to be configured to receive authenticated NTP messages from the two NTP server IP addresses via its management interface. This will require that permissions be granted between the VVoIP management VLAN and the LAN management VLAN such that NTP requests and responses can flow between the VVoIP system controller and the two NTP servers in the LAN management VLAN. If the VVoIP endpoints time is synchronized via NTP, the VVoIP controller will have to serve as their NTP server since the endpoints do not have access to the VVoIP or LAN management VLANs and should not be permitted such access.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-25782r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21523'
  tag rid: 'SV-23735r1_rule'
  tag stig_id: 'VVoIP 5250 (LAN)'
  tag gtitle: 'Deficient design: VVoIP system re: NTP'
  tag fix_id: 'F-22314r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag responsibility: 'Information Assurance Officer'
end
