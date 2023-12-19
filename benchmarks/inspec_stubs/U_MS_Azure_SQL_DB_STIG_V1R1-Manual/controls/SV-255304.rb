control 'SV-255304' do
  title 'Azure SQL Database must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the database.'
  desc "Nonrepudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Nonrepudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database. 

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables and configuring Azure SQL Database's audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to Azure SQL Database, even where the application connects to Azure SQL Database with a standard, shared account."
  desc 'check', "Obtain the list of authorized Azure SQL Database accounts in the system documentation. 

Determine if any accounts are shared. A shared account is defined as a username and password that are used by multiple individuals to log in to Azure SQL Database. Azure Active Directory accounts are not shared accounts as the group itself does not have a password. 

If accounts are determined to be shared, determine if individuals are first individually authenticated. 

If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding. 

The key is individual accountability. If this can be traced, this is not a finding. 

If accounts are determined to be shared, determine if they are directly accessible to end users. If so, this is a finding. 

Review contents of audit logs and data tables to confirm that the identity of the individual user performing the action is captured. 

If shared identifiers are found, and not accompanied by individual identifiers, this is a finding.

If collecting and keeping historical versions of a table is NOT required, this is not a finding.

Find all of the temporal tables in the database using the following query:

SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc, SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
FROM sys.tables T
JOIN sys.tables H ON T.history_table_id = H.object_id
WHERE T.temporal_type != 0
ORDER BY schema_name, table_name

Using the system documentation, determine which tables are required to be temporal tables.

If any tables listed in the documentation are not in the list created by running the above statement, this is a finding.

Ensure a field exists documenting the login and/or user who last modified the record, if this does not exist, this is a finding."
  desc 'fix', "Remove user-accessible shared accounts and use individual user IDs. 

Build/configure applications to ensure successful individual authentication prior to shared account access. 

Ensure each user's identity is received and used in audit data in all relevant circumstances. 

Design, develop, and implement a method to log use of any account to which more than one person has access. Restrict interactive access to shared accounts to the fewest persons possible."
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58977r871036_chk'
  tag severity: 'medium'
  tag gid: 'V-255304'
  tag rid: 'SV-255304r871038_rule'
  tag stig_id: 'ASQL-00-000400'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-58921r871037_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
