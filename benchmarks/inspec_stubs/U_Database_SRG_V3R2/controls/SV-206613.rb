control 'SV-206613' do
  title 'The DBMS must generate audit records when unsuccessful attempts to access security objects occur.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:
SELECT
INSERT
UPDATE
DELETE
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'If the DBMS architecture makes it impossible for any user, even with the highest privileges, to directly view or directly modify the contents of its built-in security objects, and if there are no additional, locally-defined security objects in the database(s), this is not a finding.

Review DBMS documentation to verify that audit records can be produced when the system denies or fails to complete attempts to access security objects, such as tables, views, procedures, and functions, such access to include reads, creations, modifications and deletions of data, and execution of logic.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when the system denies attempts to access security objects, such as tables, views, procedures, and functions, such access to include reads, creations, modifications and deletions of data, and execution of logic.

If they are not produced, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when other errors prevent attempts to access security object.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when it denies or fails to complete access to security objects, such as tables, views, procedures, and functions.

Configure the DBMS to produce audit records when it denies access to security objects, such as tables, views, procedures, and functions, such access to include reads, creations, modifications and deletions of data, and execution of logic.

Configure the DBMS to produce audit records when other errors prevent access to security objects, such as tables, views, procedures, and functions, such access to include reads, creations, modifications and deletions of data, and execution of logic.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6873r291507_chk'
  tag severity: 'medium'
  tag gid: 'V-206613'
  tag rid: 'SV-206613r617447_rule'
  tag stig_id: 'SRG-APP-000492-DB-000333'
  tag gtitle: 'SRG-APP-000492'
  tag fix_id: 'F-6873r291508_fix'
  tag 'documentable'
  tag legacy: ['SV-72515', 'V-58085']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
