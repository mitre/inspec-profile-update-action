control 'SV-253712' do
  title 'MariaDB must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.'
  desc 'check', 'Review the procedures for the refreshing of development/test data from production.

Review any scripts or code that exists for the movement of production data to development/test systems, or to any other location or for any other purpose.

Verify that copies of production data are not left in unprotected locations. 

If the code that exists for data movement does not comply with the organization-defined data transfer policy and/or fails to remove any copies of production data from unprotected locations, this is a finding.'
  desc 'fix', 'Modify any code used for moving data from production to development/test systems to comply with the organization-defined data transfer policy, and to ensure copies of production data are not left in unsecured locations.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57164r841659_chk'
  tag severity: 'medium'
  tag gid: 'V-253712'
  tag rid: 'SV-253712r841661_rule'
  tag stig_id: 'MADB-10-005500'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-57115r841660_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
