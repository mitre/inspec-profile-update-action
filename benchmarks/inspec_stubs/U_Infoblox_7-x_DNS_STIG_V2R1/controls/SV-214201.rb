control 'SV-214201' do
  title 'The DNS server must implement NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Note: For Infoblox DNS systems on a Classified network, this requirement is Not Applicable.

Navigate to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab.
Validate that all Key Signing Keys (KSK) and Zone Signing Keys (ZSK) utilize FIPS approved algorithms.
When complete, click "Cancel" to exit the "Properties" screen.

If non FIPS-approved algorithms are in use, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Grid DNS properties.

Toggle Advanced Mode click on "DNSSEC" tab.
Follow manual key rollover procedures and update all non-compliant Key Signing Keys (KSK) and Zone Signing Keys (ZSK) to utilize FIPS-approved algorithms.'
  impact 0.7
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15416r295866_chk'
  tag severity: 'high'
  tag gid: 'V-214201'
  tag rid: 'SV-214201r612370_rule'
  tag stig_id: 'IDNS-7X-000690'
  tag gtitle: 'SRG-APP-000514-DNS-000075'
  tag fix_id: 'F-15414r295867_fix'
  tag 'documentable'
  tag legacy: ['SV-83087', 'V-68597']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
