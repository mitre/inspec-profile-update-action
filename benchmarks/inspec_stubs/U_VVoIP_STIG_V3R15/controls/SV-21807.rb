control 'SV-21807' do
  title 'The Session Border Controller (SBC) must be configured to terminate and decrypt inbound and outbound SIP and AS-SIP sessions to ensure proper management for the transition of the SRTP/SRTCP streams.'
  desc 'The function of the SBC is to manage SIP and AS-SIP signaling messages. In order to perform its proper function in the enclave boundary, the SBC must decrypt and decode or understand the contents of SIP and AS-SIP messages. Additionally, the SBC can perform message validity checks and determine of an attack is being attempted. The SBC acts as an application level proxy and firewall for the SIP and AS-SIP signaling messages.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Ensure the DISN NIPRNet IPVS SBC is configured to terminate inbound and outbound SIP and AS-SIP sessions (messages) and decrypt the packets to determine the information needed to properly manage the transition of SRTP/SRTCP streams across the boundary. Additionally ensure the SBC establishes a new SIP or AS-SIP session for the “next hop” to the internal LSC or the far end SBC that fronts the destination MFSS. Inspect the configuration of the EBC to determine compliance with the requirement.

If SIP or AS-SIP messages are just passed through the SBC without termination and decryption, this is a finding. If the SBC is not configured to, or is not capable of, terminating and decrypting the SIP or AS-SIP messages, this is a finding. If the SBC is not configured to, or is not capable of, understanding the contents of the decrypted SIP or AS-SIP messages, this is a finding. If the SBC is not configured to establish a new SIP or AS-SIP session with the far end SBC that fronts the destination LSC or MFSS, this is a finding. If the SBC is not configured to establish a new SIP or AS-SIP session with the LSC inside the enclave, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443  from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to terminate inbound and outbound SIP and AS-SIP sessions (messages). The SBC must be configured to decrypt the packets to determine the information needed to properly manage the transition of SRTP/SRTCP streams across the boundary. Additionally ensure the SBC establishes a new SIP or AS-SIP session for the “next hop” to the internal LSC or the far end SBC that fronts the destination LSC or MFSS.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24041r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19666'
  tag rid: 'SV-21807r3_rule'
  tag stig_id: 'VVoIP 6305'
  tag gtitle: 'VVoIP 6305'
  tag fix_id: 'F-20372r2_fix'
  tag 'documentable'
end
