control 'SV-214034' do
  title 'Filestream must be disabled, unless specifically required and approved.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

The most significant potential for attacking an instance is through the use of features that expose an external interface or ad hoc execution capability. FILESTREAM integrates the SQL Server Database Engine with an NTFS file system by storing varbinary(max) binary large object (BLOB) data as files on the file system. Transact-SQL statements can insert, update, query, search, and back up FILESTREAM data.'
  desc 'check', %q(Review the system documentation to see if FileStream is in use.  If in use authorized, this is not a finding.   

If FileStream is not documented as being authorized, execute the following query.
EXEC sp_configure 'filestream access level'

If "run_value" is greater than "0", this is a finding.



This rule checks that Filestream SQL specific option is disabled.

SELECT CASE 
        WHEN EXISTS (SELECT * 
                     FROM sys.configurations 
                     WHERE Name = 'filestream access level' 
                            AND Cast(value AS INT) = 0) THEN 'No' 
        ELSE 'Yes'
      END AS TSQLFileStreamAccess;

If the above query returns "Yes" in the "FileStreamEnabled" field, this is a finding.)
  desc 'fix', "Disable the use of Filestream.

1. Delete all FILESTREAM columns from all tables. ALTER TABLE <name> DROP COLUMN <column name>
2. Disassociate tables from the FILESTREAM filegroups. ALTER TABLE <name> SET (FILESTREAM_ON = 'NULL'
3. Remove all FILESTREAM data containers. ALTER DATABASE <name> REMOVE FILE <file name>
4. Remove all FILESTREAM filegroups. ALTER DATABASE <name> REMOVE FILEGROUP <file name>.
5. Disable FILESTREAM.
EXEC sp_configure filestream_access_level, 0 
    RECONFIGURE 
6. Restart the SQL Service"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15251r313885_chk'
  tag severity: 'medium'
  tag gid: 'V-214034'
  tag rid: 'SV-214034r879587_rule'
  tag stig_id: 'SQL6-D0-016800'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-15249r313886_fix'
  tag 'documentable'
  tag legacy: ['SV-94035', 'V-79329']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
