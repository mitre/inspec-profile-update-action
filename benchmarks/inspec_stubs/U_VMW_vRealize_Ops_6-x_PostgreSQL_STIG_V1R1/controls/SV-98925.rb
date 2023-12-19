control 'SV-98925' do
  title 'vROps PostgreSQL DB contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. 

Data used for the development and testing of applications often involves copying data from production. It is important that specific procedures exist for this process, to include the conditions under which such transfer may take place, where the copies may reside, and the rules for ensuring sensitive data are not exposed.

Copies of sensitive data must not be misplaced or left in a temporary location without the proper controls.'
  desc 'check', 'Obtain the site data-transfer policy from the ISSO.

Review the policies and procedures used to ensure that all vROps data is being protected from unauthorized and unintended information transformation in accordance with site policy.

If the site data-transfer policy is not followed, this is a finding.'
  desc 'fix', 'Modify any code used for moving data from production to development/test systems to comply with the organization-defined site data-transfer policy, and to ensure copies of production data are not left in unsecured locations.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88275'
  tag rid: 'SV-98925r1_rule'
  tag stig_id: 'VROM-PG-000270'
  tag gtitle: 'SRG-APP-000243-DB-000128'
  tag fix_id: 'F-95017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
