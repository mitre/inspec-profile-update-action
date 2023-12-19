control 'SV-213908' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be owned by database/DBMS principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects in SQL Server rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Review system documentation to identify SQL Server accounts authorized to own database objects. 

If the SQL Server database ownership list does not exist or needs to be updated, this is a finding. 

The following query can be of use in making this determination: 

;with objects_cte as
(SELECT o.name, o.type_desc,
   CASE
    WHEN o.principal_id is null then s.principal_id
     ELSE o.principal_id
    END as principal_id
 FROM sys.objects o
 INNER JOIN sys.schemas s
 ON o.schema_id = s.schema_id
 WHERE o.is_ms_shipped = 0
)
SELECT cte.name, cte.type_desc, dp.name as ObjectOwner 
FROM objects_cte cte
INNER JOIN sys.database_principals dp
ON cte.principal_id = dp.principal_id
ORDER BY dp.name, cte.name

If any of the listed owners is not authorized, this is a finding.'
  desc 'fix', 'Add and/or update system documentation to include any accounts authorized for object ownership and remove any account not authorized. 

To change the schema owning a database object in SQL Server, use this code as an example: 

USE AdventureWorks2012;  
GO  
ALTER SCHEMA HumanResources TRANSFER Person.Address;  
GO  

Caution: This can break code. This Fix should be implemented in conjunction with corrections to such code. Test before deploying in production. Deploy during a scheduled maintenance window.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15126r313156_chk'
  tag severity: 'medium'
  tag gid: 'V-213908'
  tag rid: 'SV-213908r879586_rule'
  tag stig_id: 'SQL6-D0-001300'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-15124r313157_fix'
  tag 'documentable'
  tag legacy: ['SV-93785', 'V-79079']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
