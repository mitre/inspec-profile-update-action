control 'SV-222573' do
  title 'Applications making SAML assertions must use FIPS-approved random numbers in the generation of SessionIndex in the SAML element AuthnStatement.'
  desc 'A predictable SessionIndex could lead to an attacker computing a future SessionIndex, thereby, possibly compromising the application.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Interview the system administrator, review the application components, and the application requirements to determine if the application uses SAML assertions.

If the application does not use SAML assertions, the requirement is not applicable.

Review the application documentation and interview he application administrator to identify the cryptographic modules used by the application.

Access the NIST site to determine if the cryptographic modules used by the application have been FIPS-validated.

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the application is using cryptographic modules that are not FIPS-validated when generating the SessionIndex in the SAML AuthnStatement, this is a finding.'
  desc 'fix', 'Configure the application to use a FIPS-validated cryptographic module.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24243r493627_chk'
  tag severity: 'medium'
  tag gid: 'V-222573'
  tag rid: 'SV-222573r879885_rule'
  tag stig_id: 'APSC-DV-002050'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-24232r493628_fix'
  tag 'documentable'
  tag legacy: ['SV-84819', 'V-70197']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
