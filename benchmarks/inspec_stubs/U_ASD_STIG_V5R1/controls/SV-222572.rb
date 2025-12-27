control 'SV-222572' do
  title 'The application must utilize FIPS-validated cryptographic modules when protecting unclassified information that requires cryptographic protection.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Interview the system administrator, review the application components, and the application requirements to determine if the application processes data requiring cryptographic protection.

Review the application documentation and interview the application administrator to identify the cryptographic modules used by the application.

Access the NIST site to determine if the cryptographic modules used by the application have been FIPS-validated.

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the application is using cryptographic modules that are not FIPS-validated to protect unclassified data, this is a finding.'
  desc 'fix', 'Configure the application to use a FIPS-validated cryptographic module.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24242r493624_chk'
  tag severity: 'medium'
  tag gid: 'V-222572'
  tag rid: 'SV-222572r508029_rule'
  tag stig_id: 'APSC-DV-002040'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-24231r493625_fix'
  tag 'documentable'
  tag legacy: ['SV-84817', 'V-70195']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
