control 'SV-206612' do
  title 'The DBMS must be able to generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', 'If the DBMS architecture makes it impossible for any user, even with the highest privileges, to directly view or directly modify the contents of its built-in security objects, and if there are no additional, locally-defined security objects in the database(s), this is not a finding.

Review DBMS documentation to verify that audit records can be produced when security objects, such as tables, views, procedures, and functions, are accessed, to include reads, creations, modifications and deletions of data, and execution of logic.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when security objects, such as tables, views, procedures, and functions, are accessed, to include reads, creations, modifications and deletions of data, and execution of logic.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when security objects, such as tables, views, procedures, and functions, are accessed.

Configure the DBMS to produce audit records when security objects, such as tables, views, procedures, and functions, are accessed, to include reads, creations, modifications and deletions of data, and execution of logic.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6872r291504_chk'
  tag severity: 'medium'
  tag gid: 'V-206612'
  tag rid: 'SV-206612r617447_rule'
  tag stig_id: 'SRG-APP-000492-DB-000332'
  tag gtitle: 'SRG-APP-000492'
  tag fix_id: 'F-6872r291505_fix'
  tag 'documentable'
  tag legacy: ['SV-72513', 'V-58083']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
