control 'SV-213903' do
  title 'SQL Server must protect against a user falsely repudiating by use of system-versioned tables (Temporal Tables).'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring SQL Server's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to SQL Server, even where the application connects to SQL Server with a standard, shared account. 

Applications should use temporal tables to track the changes and history of sensitive data."
  desc 'check', "Check the server documentation to determine if collecting and keeping historical versions of a table is required.

If collecting and keeping historical versions of a table is NOT required, this is not a finding.

Find all of the temporal tables in the database using the following query:

SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc, SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
FROM sys.tables T
JOIN sys.tables H ON T.history_table_id = H.object_id
WHERE T.temporal_type != 0
ORDER BY schema_name, table_name

Using the system documentation, determine which tables are required to be temporal tables.

If any tables listed in the documentation are not in the list created by running the above statement, this is a finding.

Ensure a field exists documenting the login and/or user who last modified the record. 

If this does not exist, this is a finding."
  desc 'fix', "Alter sensitive tables to utilize system versioning.

Alter non-temporal table to define periods for system versioning .

ALTER TABLE InsurancePolicy 
ADD PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime),   
SysStartTime datetime2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT GETUTCDATE(),  
SysEndTime datetime2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.99999999');  
 
ALTER TABLE InsurancePolicy SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE=dbo.InsurancePolicyHistory));

https://docs.microsoft.com/sql/t-sql/statements/alter-table-transact-sql?view=sql-server-2016#system_versionin"
  impact 0.3
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15121r313141_chk'
  tag severity: 'low'
  tag gid: 'V-213903'
  tag rid: 'SV-213903r508025_rule'
  tag stig_id: 'SQL6-D0-000500'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-15119r313142_fix'
  tag 'documentable'
  tag legacy: ['SV-93775', 'V-79069']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
