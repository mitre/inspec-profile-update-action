control 'SV-21805' do
  title 'The Customer Edge Router (CE-R) must filter inbound AS-SIP-TLS traffic addressed to the local Session Border Controller (SBC) based on the source address of the signaling messages.'
  desc 'The CE-R (premise or perimeter) router is the first line of defense at the gateway to the enclave or LAN. The data firewall and SBC functions are the second line of defense. The SBC processes VVoIP traffic in the form of AS-SIP-TLS and SRTP/SRTCP packets, and the CE-R must forward these packets to the SBC. A filter performed by the CE-R to prevent a denial-of-service is to filter the AS-SIP-TLS packets based on their source address. Within the DISN IPVS network, Local Session Controllers (LSC) only signal to their assigned Multi-Function Soft Switch (MFSS) and its backup. MFSSs are only to signal with their assigned LSCs, for which they are primary or backup, and other MFSSs. To support this, the SBC is required to authenticate the source of, and validate the integrity of, the signaling packets it receives and only process authenticated and valid packets, thereby only signaling with the appropriate devices. Still, the SBC could be flooded and overloaded with too many unauthenticated or invalid signaling packets. The CE-R can help prevent this by preventing signaling packets that are not sourced from authorized devices from ever reaching the SBC.'
  desc 'check', 'Review site documentation to confirm the CE-R filters inbound SIP and AS-SIP traffic addressed to the local SBC based on the source address of the signaling messages. This supports the VVoIP system connecting to the DISN WAN for VVoIP transport between enclaves and the system providing Assured Services to any Command and Control (C2) user (Special-C2, C2, or C2-R). Permit inbound signaling messages sourced as follows: 
- When the enclave contains one or more Local Session Controllers (LSCs), filter on the IP addresses of the SBCs fronting the primary and secondary MFSSs associated with the enclave.
- When the enclave contains an MFSS filter based on IP addresses of SBCs fronting the LSCs associated with the SS.

If the CE-R does not filter inbound SIP and AS-SIP traffic addressed to the local SBC based on the source address of the signaling messages, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Implement the CE-R to filter inbound SIP and AS-SIP traffic addressed to the local SBC based on the source address of the signaling messages.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.3
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24034r3_chk'
  tag severity: 'low'
  tag gid: 'V-19664'
  tag rid: 'SV-21805r4_rule'
  tag stig_id: 'VVoIP 6215'
  tag gtitle: 'VVoIP 6215'
  tag fix_id: 'F-20370r3_fix'
  tag 'documentable'
end
