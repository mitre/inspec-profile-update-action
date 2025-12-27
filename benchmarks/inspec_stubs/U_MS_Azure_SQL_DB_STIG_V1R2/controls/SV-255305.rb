control 'SV-255305' do
  title 'Azure SQL Database must protect against a user falsely repudiating by use of system-versioned tables (Temporal Tables).'
  desc "Nonrepudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Nonrepudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring the DBMS's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, shared account. 

If the computer account of a remote computer is granted access to SQL Server, any service or scheduled task running as NT AUTHORITY\\SYSTEM or NT AUTHORITY\\NETWORK SERVICE can log into the instance and perform actions. These actions cannot be traced back to a specific user or process."
  desc 'check', %q(Check the server documentation to determine if collecting and keeping historical versions of a table is required.

If collecting and keeping historical versions of a table is NOT required, this is not a finding.

Find all of the temporal tables in the database using the following query:

SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc, SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
FROM sys.tables T
JOIN sys.tables H ON T.history_table_id = H.object_id
WHERE T.temporal_type != 0
ORDER BY schema_name, table_name

Using the system documentation, determine which tables are required to be temporal tables.

If any tables listed in the documentation are not in the list created by running the above statement, this is a finding.

Ensure a field exists documenting the login and/or user who last modified the record. If this does not exist, this is a finding.

Review the system documentation to determine the history retention period. 
Navigate to the table in Object Explorer. Right-click on the table, and then select Script Table As >> CREATE To >> New Query Editor Window.

Locate the line that contains "SYSTEM_VERSIONING".
Locate the text that states "HISTORY_RETENTION_PERIOD".

If this text is missing, or is set to a value less than the documented history retention period, this is a finding.)
  desc 'fix', "Alter sensitive tables to utilize system versioning.

--Alter non-temporal table to define periods for system versioning
ALTER TABLE <MyTableName>
ADD PERIOD FOR SYSTEM_TIME (SysStartTime, SysEndTime),
SysStartTime datetime2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL
    DEFAULT SYSUTCDATETIME(),
SysEndTime datetime2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL
    DEFAULT CONVERT(DATETIME2, '9999-12-31 23:59:59.99999999') ;

--Enable system versioning with 1 year retention for historical data
ALTER TABLE <MyTableName>
SET (SYSTEM_VERSIONING = ON (HISTORY_RETENTION_PERIOD = 1 YEAR)) ;

https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-table-transact-sql?view=azuresqldb-current#system_versioning"
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58978r871039_chk'
  tag severity: 'medium'
  tag gid: 'V-255305'
  tag rid: 'SV-255305r879554_rule'
  tag stig_id: 'ASQL-00-000500'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-58922r871040_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
