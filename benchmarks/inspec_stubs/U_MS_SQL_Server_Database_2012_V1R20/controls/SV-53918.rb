control 'SV-53918' do
  title 'SQL Server utilizing Discretionary Access Control (DAC) must enforce a policy that limits propagation of access rights.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment.

DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions. DAC models have the potential for the access controls to propagate without limit, resulting in unauthorized access to said objects.

When applications provide a discretionary access control mechanism, the application must be able to limit the propagation of those access rights.

The DBMS must ensure the recipient of object permissions possesses only the access intended. The database must enforce the ability to limit unauthorized rights propagation. If propagation is not prevented, users can continue to grant rights to other users without limit.'
  desc 'check', "Check for rights propagation assignment to database permissions by running the following query:

USE <name of database being reviewed>;
SELECT * 
FROM sys.database_permissions
WHERE state_desc = 'GRANT_WITH_GRANT_OPTION';

If any of the permissions listed have not been documented and approved as requiring GRANT_WITH_GRANT_OPTION, this is a finding."
  desc 'fix', 'Document and obtain approval for each GRANT_WITH_GRANT_OPTION that is required.

Correct each unapproved GRANT_WITH_GRANT_OPTION with REVOKE and GRANT statements of the form (replacing "UPDATE" with the actual permission at issue):
REVOKE UPDATE ON SampleTable FROM SampleUserOrRole CASCADE;
GRANT UPDATE ON SampleTable TO SampleRole;  -- Note, no WITH GRANT OPTION clause here.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47931r3_chk'
  tag severity: 'medium'
  tag gid: 'V-41394'
  tag rid: 'SV-53918r3_rule'
  tag stig_id: 'SQL2-00-011050'
  tag gtitle: 'SRG-APP-000085-DB-000038'
  tag fix_id: 'F-46818r4_fix'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
