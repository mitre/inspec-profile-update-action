control 'SV-20178' do
  title 'Sensitive or Personally Identifiable Information (PII) must not be transferred between an RFID tag and RFID scanner unless the information is encrypted using a FIPS 140-2 validated encryption module.'
  desc 'Sensitive or PII info could be compromised if it is not encrypted because adversaries often can intercept wireless signals transmitted between an RFID interrogator and tag.  Using FIPS 140-2 validated encryption modules provides assurance that the implementation of the cryptography is correct.'
  desc 'check', 'Interview the IAO to verifiy if sensitive or PII data is stored on the RFID tag.  If it is not, encryption of data transmitted between the RFID Tag and Scanner is not required.  If it is, perform the following:

- Verify that the data on the tag is either stored in an encrypted form on the tag (an encryption module used to encrypt the data before it is stored and the module is 140-2 validated), or
- Verify the data being transmitted between the tag and scanned is encrypted before it is transmitted to the scanner with a FIPS 140-2 validated encryption module.
Mark as a finding if either of these requirements is not met.'
  desc 'fix', 'Procure RFID tags that integrate 140-2 validated encryption modules or congure the RFID system such that data is encrypted with a FIPS 140-2 validated encryption module prior to being written to the tag.'
  impact 0.3
  ref 'DPMS Target RFID'
  tag check_id: 'C-22302r1_chk'
  tag severity: 'low'
  tag gid: 'V-18620'
  tag rid: 'SV-20178r1_rule'
  tag stig_id: 'WIR0510'
  tag gtitle: 'RFID scanner to tag security compliant'
  tag fix_id: 'F-34077r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end
