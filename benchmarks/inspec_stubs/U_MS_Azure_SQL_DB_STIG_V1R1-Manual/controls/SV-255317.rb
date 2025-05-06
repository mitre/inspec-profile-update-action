control 'SV-255317' do
  title 'Azure SQL Database must restrict execution of stored procedures and functions that utilize [execute as] to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation by "Execute As" must be utilized only where necessary and protected from misuse.'
  desc 'check', 'Review the system documentation to obtain a listing of stored procedures and functions that utilize impersonation. Execute the following query:

SELECT S.name AS schema_name, O.name AS module_name,
USER_NAME(CASE M.execute_as_principal_id 
               WHEN -2 THEN COALESCE(O.principal_id, S.principal_id)
               ELSE M.execute_as_principal_id
          END) AS execute_as
FROM sys.sql_modules M
    JOIN sys.objects O ON M.object_id = O.object_id
    JOIN sys.schemas S ON O.schema_id = S.schema_id
WHERE execute_as_principal_id IS NOT NULL
ORDER BY schema_name, module_name

If any procedures or functions are returned that are not documented, this is a finding.'
  desc 'fix', 'Alter stored procedures and functions to remove the "EXECUTE AS" statement.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58990r871075_chk'
  tag severity: 'medium'
  tag gid: 'V-255317'
  tag rid: 'SV-255317r871077_rule'
  tag stig_id: 'ASQL-00-002900'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-58934r871076_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
