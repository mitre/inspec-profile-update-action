control 'SV-53671' do
  title 'SQL Server utilizing Discretionary Access Control (DAC) must enforce a policy that limits propagation of access rights.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write).

These DAC concepts extend to the server level.  Server instances have the potential for the access controls to propagate without limit, resulting in unauthorized access.

The DBMS must ensure the recipient of server permissions possesses only the access intended. The DBMS must enforce the ability to limit unauthorized rights propagation. If propagation is not prevented, users can continue to grant rights to other users without limit.'
  desc 'check', "Check for rights propagation assignment to DBMS server permissions by running the following query:

USE master;
SELECT * 
FROM sys.server_permissions
WHERE state_desc = 'GRANT_WITH_GRANT_OPTION';

If any of the permissions listed have not been documented and approved as requiring GRANT_WITH_GRANT_OPTION, this is a finding."
  desc 'fix', 'Document and obtain approval for each GRANT_WITH_GRANT_OPTION that is required.

Correct each unapproved GRANT_WITH_GRANT_OPTION with REVOKE and GRANT statements of the form (replacing "ALTER ANY DATABASE" with the actual server permission at issue):

REVOKE ALTER ANY DATABASE FROM SampleLoginOrServerRole CASCADE;
GRANT ALTER ANY DATABASE TO SampleServerRole;  -- Note, no WITH GRANT OPTION clause here.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47794r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41204'
  tag rid: 'SV-53671r4_rule'
  tag stig_id: 'SQL2-00-011000'
  tag gtitle: 'SRG-APP-000085-DB-000038'
  tag fix_id: 'F-46596r4_fix'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
