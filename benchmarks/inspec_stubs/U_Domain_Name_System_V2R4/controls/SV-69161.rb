control 'SV-69161' do
  title 'The DNS server must implement NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Review the DNS implementation and configuration files to ensure FIPS-validated cryptography is being used when provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information that requires confidentiality.

If the DNS configuration does not use FIPS-validated cryptography, this is a finding.'
  desc 'fix', 'Configure the DNS implementation to use NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55541r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54915'
  tag rid: 'SV-69161r1_rule'
  tag stig_id: 'SRG-APP-000514-DNS-000075'
  tag gtitle: 'SRG-APP-000514-DNS-000075'
  tag fix_id: 'F-59777r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
