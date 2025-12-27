control 'SV-20154' do
  title 'Site WMAN systems that transmit unclassified data must implement required data encryption controls.'
  desc 'Sensitive DoD data could be exposed to a hacker.'
  desc 'check', 'Detailed policy requirements:

Site WMAN systems that transmit unclassified data must implement the following data encryption controls:

- For tactical WMAN systems or commercial WMAN systems operated in a tactical environment:
 --The WMAN system must implement FIPS 140-2 validated encryption to protect the ISO OSI Layer 2 radio data frames.  The WMAN system must be configured for AES-CCM encryption, if supported by the WMAN system.
 --The WMAN system must implement FIPS 140-2 validated encryption to protect the ISO OSI Layer 3 data being transmitted.
 
- For tactical WMAN systems or commercial WMAN systems operated in a non-tactical environment and for WMAN bridges:  
 --The WMAN system must implement FIPS 140-2 validated encryption at ISO OSI Layer 2 or 3.

Check Procedures:

Verify with the IAO that site WMAN systems transmitting unclassified data implement the following data encryption controls:

For tactical WMAN systems or commercial WMAN systems operated in a tactical environment:
- The WMAN system must implement FIPS 140-2 validated encryption to protect the ISO OSI Layer 2 radio data frames.  The WMAN system will be configured for AES-CCM encryption, if supported by the WMAN system.
- The WMAN system must implement FIPS 140-2 validated encryption to protect the ISO OSI Layer 3 data being transmitted.
 
For tactical WMAN systems or commercial WMAN systems operated in a non-tactical environment:  
- The WMAN system must implement FIPS 140-2 validated encryption at ISO OSI Layer 2 or 3.

Mark as a finding if these requirements are not met.'
  desc 'fix', 'Comply with policy.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-22270r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18603'
  tag rid: 'SV-20154r1_rule'
  tag stig_id: 'WIR0325'
  tag gtitle: 'Encryption for unclass WMAN is compliant'
  tag fix_id: 'F-14436r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end
