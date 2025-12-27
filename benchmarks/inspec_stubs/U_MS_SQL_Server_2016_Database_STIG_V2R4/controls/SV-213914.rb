control 'SV-213914' do
  title 'SQL Server must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'Determine elements of security functionality (lists of permissions, additional authentication information, stored procedures, application specific auditing, etc.) that are being housed inside SQL server.

For any elements found, check SQL Server to determine if these objects or code implementing security functionality are located in a separate security domain, such as a separate database, schema, or table created specifically for security functionality.

If the database is a SQL Server default database (master, msdb, model, tempdb), this is NA.

Run the following query to list all the user-defined databases:

SELECT Name 
FROM sys.databases 
WHERE database_id > 4 
ORDER BY 1;

Review the database structure to determine where security related functionality is stored. If security-related database objects or code are not kept separate, this is a finding.'
  desc 'fix', 'Check the server documentation, locate security-related database objects and code in a separate database, schema, table, or other separate security domain from database objects and code implementing application logic.  

Microsoft SQL Server 2005 introduced the concept of database object schemas. Schemas are analogous to separate namespaces or containers used to store database objects. Security permissions apply to schemas, making them an important tool for separating and protecting database objects based on access rights. Schemas reduce the work required, and improve the flexibility, for security-related administration of a database.

User-schema separation allows for more flexibility in managing database object permissions. A schema is a named container for database objects, which allows the user to group objects into separate namespaces.

Where possible, locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic. In all cases, use GRANT, REVOKE, DENY, ALTER ROLE … ADD MEMBER … and/or ALTER ROLE …. DROP MEMBER statements to add and remove permissions on server-level and database-level security-related objects to provide effective isolation.'
  impact 0.3
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15132r822447_chk'
  tag severity: 'low'
  tag gid: 'V-213914'
  tag rid: 'SV-213914r822449_rule'
  tag stig_id: 'SQL6-D0-001900'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-15130r822448_fix'
  tag 'documentable'
  tag legacy: ['SV-93797', 'V-79091']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
