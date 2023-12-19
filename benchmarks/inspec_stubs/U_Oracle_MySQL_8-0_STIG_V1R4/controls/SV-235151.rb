control 'SV-235151' do
  title 'The MySQL Database Server 8.0 must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.

The mysql database is the system database. It contains tables that store information required by the MySQL server as it runs.

The INFORMATION_SCHEMA provides access to database metadata, information about the MySQL server such as the name of a database or table, the data type of a column, or access privileges. Other terms sometimes used for this information are data dictionary and system catalog.

The MySQL Performance Schema is a feature for monitoring MySQL Server execution at a low level. The Performance Schema has these characteristics: The Performance Schema provides a way to inspect internal execution of the server at runtime. It is implemented using the PERFORMANCE_SCHEMA storage engine and the performance_schema database. The PERFORMANCE_SCHEMA storage engine collects event data using “instrumentation points” in server source code. Tables in the Performance Schema are in-memory tables that use no persistent on-disk storage.

MySQL 8.0 includes the sys schema, a set of objects that helps DBAs and developers interpret data collected by the Performance Schema. The sys schema objects can be used for typical tuning and diagnosis use cases.'
  desc 'check', "Determine elements of security functionality (lists of permissions, additional authentication information, stored procedures, application specific auditing, etc.) which are being housed inside the MySQL server.

For any elements found, check MySQL to determine if these objects or code implementing security functionality are located in a separate security domain, such as a separate database, schema, or table created specifically for security functionality.

In more generic data terms, MySQL is a single database per instance with multiple schemas. MySQL uses the term database and schema interchangeably. 

Run the following query to list all the user-defined schemas.
SELECT 
    `SCHEMATA`.`SCHEMA_NAME`
FROM `information_schema`.`SCHEMATA` 
where `SCHEMA_NAME` not in ('mysql', 'information_schema', 'performance_schema','sys');

Review the database structure to determine where security-related functionality is stored. 

If security-related database objects or code are not kept separate, this is a finding."
  desc 'fix', 'Check the server documentation, locate security-related database objects and code in a separate database, schema, table, or other separate security domain from database objects and code implementing application logic. 

Schemas, also referred to as databases, are analogous to separate namespaces or containers used to store database objects. Security permissions apply to schemas, making them an important tool for separating and protecting database objects based on access rights. Schemas reduce the work required, and improve the flexibility, for security-related administration of a database. A MySQL schema is a named container for database objects, which allows objects to be grouped into separate namespaces.

Where possible, locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic. In all cases, use GRANT, REVOKE, … , DROP ROLE statements to add and remove permissions on administrative/server-level and schema/database-level, or database object security-related objects to provide effective isolation.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38370r623573_chk'
  tag severity: 'medium'
  tag gid: 'V-235151'
  tag rid: 'SV-235151r879643_rule'
  tag stig_id: 'MYS8-00-006500'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-38333r623574_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
