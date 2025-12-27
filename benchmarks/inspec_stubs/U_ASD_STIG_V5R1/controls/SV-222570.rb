control 'SV-222570' do
  title 'The application must utilize FIPS-validated cryptographic modules when signing application components.'
  desc 'Applications that distribute components of the application must sign the components to provide an identity assurance to consumers of the application component. Components can include application messages or application code.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to validate the author of application components. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance the modules have been tested and validated.

If the application resides on a National Security System (NSS) it must not use algorithms weaker than SHA-384.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify the cryptographic modules used by the application.

Review the application components and application requirements. Interview application developers and application admins to determine if code signing is performed on distributable application components, files or packages.  

For example, a developer may sign application code components or an admin may sign application files or packages in order to provide application consumers with integrity assurances.

If signing has been identified in the application security plan as not being required and if a documented acceptance of risk is provided, this is not a finding.

Have the application admin or the developer demonstrate how the signing algorithms are used and how signing of components including files, code and packages is performed.

While SHA1 is currently FIPS-140-2 approved, due to known vulnerabilities with this algorithm, DoD PKI policy prohibits the use of SHA1 as of December 2016.  See DoD CIO Memo Subject: Revised Schedule to Update DoD Public Key Infrastructure Certificates to Secure Hash Algorithm-256. 

If the application signing process does not use FIPS validated cryptographic modules, or if the signing process includes SHA1 or MD5 hashing algorithms, this is a finding.'
  desc 'fix', 'Utilize FIPS-validated algorithms when signing application components.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24240r493618_chk'
  tag severity: 'medium'
  tag gid: 'V-222570'
  tag rid: 'SV-222570r508029_rule'
  tag stig_id: 'APSC-DV-002020'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-24229r493619_fix'
  tag 'documentable'
  tag legacy: ['SV-84813', 'V-70191']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
