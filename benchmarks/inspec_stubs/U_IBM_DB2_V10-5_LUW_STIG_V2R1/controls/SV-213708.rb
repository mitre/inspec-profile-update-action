control 'SV-213708' do
  title 'Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.'
  desc 'Applications, including DBMSs, must prevent unauthorized and unintended information transfer via shared system resources. 

Data used for the development and testing of applications often involves copying data from production. It is important that specific procedures exist for this process, to include the conditions under which such transfer may take place, where the copies may reside, and the rules for ensuring sensitive data are not exposed.

Copies of sensitive data must not be misplaced or left in a temporary location without the proper controls.'
  desc 'check', 'Verify there are proper procedures in place for the transfer of development/test data from production. Review any scripts or code that exists for the movement of production data to development/test and verify copies of production data are not left in unprotected locations.

If there is no documented procedure for data movement from production to development/test, this is a finding.

If data movement code that copies from production to development/test does exist and leaves any copies of production data in unprotected locations, this is a finding.'
  desc 'fix', 'Create and document a process for moving data from production to development/test systems and follow the process.

Modify any code used for moving data from production to development/test systems to ensure copies of production data are not left in unsecured locations.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14929r295173_chk'
  tag severity: 'medium'
  tag gid: 'V-213708'
  tag rid: 'SV-213708r879649_rule'
  tag stig_id: 'DB2X-00-005600'
  tag gtitle: 'SRG-APP-000243-DB-000128'
  tag fix_id: 'F-14927r295174_fix'
  tag 'documentable'
  tag legacy: ['SV-89179', 'V-74505']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
