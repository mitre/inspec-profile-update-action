control 'SV-20156' do
  title 'A WMAN system transmitting classified data must implement required data encryption controls.'
  desc 'If not compliant, classified data could be compromised.'
  desc 'check', 'Detailed Policy Requirements:

Site WMAN systems that transmit classified data must implement the following data encryption controls:

- The WMAN system must implement FIPS 140-2 validated encryption to protect the ISO OSI Layer 2 radio data frames.  The WMAN system will be configured for AES-CCM encryption, if supported by the WMAN system.  (Not required for classified WMAN bridges.)
- The WMAN system must implement NSA Type 1 certified High Assurance Internet Protocol Encryptor (HAIPE) encryption, other NSA Type 1 certified encryption, or NSA approved Suite B overlay encryption at ISO OSI Layer 3 to protect data being transmitted.

Check Procedures:

Review the WMAN product specification sheets.  
- Verify FIPS 140-2 validated encryption is being used at OSI Layer 2 to protect the radio data frames.
- Determine if the system supports AES-CCM encryption.  If yes, verify the system has been configured for AES-CCM encryption.
 - Verify NSA Type 1 certified High Assurance Internet Protocol Encryptor (HAIPE) encryption, other NSA Type 1 certified encryption, or NSA approved Suite B overlay encryption is being used at OSI Layer 3 to protect data being transmitted.

Mark as a finding if any of these requirements have not been met.'
  desc 'fix', 'Comply with policy.'
  impact 0.7
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-22272r1_chk'
  tag severity: 'high'
  tag gid: 'V-18604'
  tag rid: 'SV-20156r1_rule'
  tag stig_id: 'WIR0330'
  tag gtitle: 'Classified WMAN encryption compliant'
  tag fix_id: 'F-14436r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end
