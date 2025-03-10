control 'SV-21809' do
  title 'The Session Border Controller (SBC) must be configured to only process signaling packets whose integrity is validated.'
  desc 'The validation of signaling packet integrity is required to ensure the packet has not been altered in transit. Packets can be altered during uncontrollable network events, such as bit errors and packet truncation that would cause the packet to contain erroneous information. Packets containing detectable errors must not be processed. Packets can also be modified by a man-in-the-middle attack. The current Unified Capabilities Requirements (UCR) document specifies the hashing algorithm to be used during transmission.'
  desc 'check', 'Interview the ISSO to confirm compliance with the following requirement: 

Ensure the DISN NIPRNet IPVS SBC is configured to only process signaling packets whose integrity is validated. Inspect the configurations of the EBC to determine compliance with the requirement.

If the SBC does not validate the integrity of the received signaling packets, this is a finding. If the SBC is not configured to drop packets whose integrity is not validated, this is a finding.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Ensure the DISN NIPRNet IPVS SBC is configured to only process signaling packets whose integrity is validated. The current Unified Capabilities Requirements (UCR) document specifies the hashing algorithm to be used during transmission.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24045r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19668'
  tag rid: 'SV-21809r3_rule'
  tag stig_id: 'VVoIP 6315'
  tag gtitle: 'VVoIP 6315'
  tag fix_id: 'F-20374r2_fix'
  tag 'documentable'
end
