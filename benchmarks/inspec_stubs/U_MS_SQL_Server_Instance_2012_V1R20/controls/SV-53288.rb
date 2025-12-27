control 'SV-53288' do
  title 'SQL Server must specifically prohibit or restrict the use of unauthorized functions and services in each instance.'
  desc 'SQL Server is capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Additionally, it is sometimes convenient to provide multiple services from a single component of an information system (e.g., email and web services), but doing so increases risk over limiting the services provided by any one component.'
  desc 'check', "Review the list of user-defined Stored Procedures and Functions by running the following SQL query:
EXEC sp_MSforeachdb
'
DECLARE @nCount integer;

SELECT @nCount = Count(*)
  FROM [?].sys.objects
 WHERE type in (''FN'', ''P'')
   AND is_ms_shipped <> 1;

IF @nCount > 0
SELECT ''?'' AS ''Table Name'', *
  FROM [?].sys.objects
 WHERE type in (''FN'', ''P'')
   AND is_ms_shipped <> 1;
'
;

If any user-defined Stored Procedures and Functions are unauthorized and therefore should be prohibited or restricted and are not, this is a finding."
  desc 'fix', "To remove a function from SQL Server, run the following SQL Script:
DROP FUNCTION <'function name'>

To remove a Stored Procedure from SQL Server, run the following SQL Script:
DROP PROCEDURE <'stored procedure name'>

If the user-defined Stored Procedures and Functions need to remain available, but access needs to be more restricted, then the user-defined Stored Procedures and Functions should be moved to a separate schema or database that has more restrictive access."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47589r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40934'
  tag rid: 'SV-53288r3_rule'
  tag stig_id: 'SQL2-00-017300'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-46216r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
