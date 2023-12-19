control 'SV-222571' do
  title 'The application must utilize FIPS-validated cryptographic modules when generating cryptographic hashes.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

If the application resides on a National Security System (NSS) it must not use a hashing algorithm weaker than SHA-384.'
  desc 'check', 'Review the application components and the application requirements to determine if the application is capable of generating cryptographic hashes.

Review the application documentation and interview the application developer or administrator to identify the cryptographic modules used by the application.

If hashing of application components has been identified in the application security plan as not being required and if a documented acceptance of risk is provided, this is not a finding.

Have the application admin or the developer demonstrate how the application generates hashes and what hashing algorithms are used when generating a hash value.

While SHA1 is currently FIPS-140-2 approved, due to known vulnerabilities with this algorithm, DoD PKI policy prohibits the use of SHA1 as of December 2016.  See DoD CIO Memo Subject: Revised Schedule to Update DoD Public Key Infrastructure Certificates to Secure Hash Algorithm-256. 

If the application resides on a National Security System (NSS) and uses an algorithm weaker than SHA-384, this is a finding.

If FIPS-validated cryptographic modules are not used when generating hashes or if the application is configured to use the MD5 or SHA1 hashing algorithm, this is a finding.'
  desc 'fix', 'Configure the application to use a FIPS-validated hashing algorithm when creating a cryptographic hash.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24241r493621_chk'
  tag severity: 'medium'
  tag gid: 'V-222571'
  tag rid: 'SV-222571r849477_rule'
  tag stig_id: 'APSC-DV-002030'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-24230r493622_fix'
  tag 'documentable'
  tag legacy: ['SV-84815', 'V-70193']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
