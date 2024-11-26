control 'SV-255311' do
  title 'The Azure SQL Database and associated applications must reserve the use of dynamic code execution for situations that require it.'
  desc 'With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

The principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', "Review the system documentation to obtain a listing of stored procedures and functions that utilize dynamic code execution. Execute the following query:

DECLARE @tblDynamicQuery TABLE (ID INT identity(1,1), ProcToExecuteDynSQL VARCHAR(500))
INSERT INTO @tblDynamicQuery(ProcToExecuteDynSQL) values('EXEC[ (]@')
INSERT INTO @tblDynamicQuery(ProcToExecuteDynSQL) values('EXECUTE[ (]@')
INSERT INTO @tblDynamicQuery(ProcToExecuteDynSQL) values('SP_EXECUTESQL[ (]@')

SELECT 
   QUOTENAME(DB_Name()) DB_Name,
   QUOTENAME(SCHEMA_NAME([schema_id])) + '.' + QUOTENAME(name) Name, QUOTENAME(type_desc)  ObjectType
FROM sys.objects o
WHERE o.is_ms_shipped = 0 and 
o.object_id IN (
   SELECT m.object_id
   FROM sys.sql_modules m 
   JOIN @tblDynamicQuery dsql ON REPLACE(REPLACE(REPLACE(m.definition,CHAR(32),'()'),')(',''),'()',CHAR(32)) like '%' + dsql.ProcToExecuteDynSQL + '%')

If any procedures or functions are returned that are not documented, this is a finding."
  desc 'fix', 'Where dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, modify the code to do so.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58984r871057_chk'
  tag severity: 'medium'
  tag gid: 'V-255311'
  tag rid: 'SV-255311r871059_rule'
  tag stig_id: 'ASQL-00-002200'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-58928r871058_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
