control 'SV-239210' do
  title 'Data from the vPostgres database must be protected from unauthorized transfer.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. 

Data used for the development and testing of applications often involves copying data from production. It is important that specific procedures exist for this process, including the conditions under which such transfer may take place, where the copies may reside, and the rules for ensuring sensitive data is not exposed.

Copies of sensitive data must not be misplaced or left in a temporary location without the proper controls.'
  desc 'check', 'Obtain the site data-transfer policy from the ISSO.

Review the policies and procedures used to ensure that all vRA data is being protected from unauthorized and unintended information transformation in accordance with site policy.

If the site data-transfer policy is not followed, this is a finding.'
  desc 'fix', 'Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy and to ensure that copies of production data are not left in unsecured locations.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42443r679001_chk'
  tag severity: 'medium'
  tag gid: 'V-239210'
  tag rid: 'SV-239210r679003_rule'
  tag stig_id: 'VCPG-67-000018'
  tag gtitle: 'SRG-APP-000243-DB-000128'
  tag fix_id: 'F-42402r679002_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
