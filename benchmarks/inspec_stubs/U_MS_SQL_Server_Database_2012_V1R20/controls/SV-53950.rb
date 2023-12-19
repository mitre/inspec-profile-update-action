control 'SV-53950' do
  title 'SQL Server must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.

Data used for the development and testing of applications often involves copying data from production. It is important that specific procedures exist for this process, so copies of sensitive data are not misplaced or left in a temporary location without the proper controls.'
  desc 'check', 'Verify there are proper procedures in place for the transfer of development/test data from production. Review any scripts or code that exists for the movement of production data to development/test and verify copies of production data are not left in unprotected locations.

If there is no documented procedure for data movement from production to development/test, this is a finding.

If data movement code that copies from production to development/test does exist and leaves any copies of production data in unprotected locations, this is a finding.'
  desc 'fix', 'Create and document a process for moving data from production to development/test systems and follow the process.

Modify any code used for moving data from production to development/test systems to ensure copies of production data are not left in unsecured locations.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47956r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41421'
  tag rid: 'SV-53950r2_rule'
  tag stig_id: 'SQL2-00-021800'
  tag gtitle: 'SRG-APP-000243-DB-000128'
  tag fix_id: 'F-46850r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
