control 'SV-235143' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled.

Database Management Systems (DBMSs) must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', "Review vendor documentation and vendor websites to identify vendor-provided demonstration or sample databases, database applications, objects, and files. Note: MySQL does not include any in MySQL Database Server 8.0.

Review the MySQL Database Server 8.0 to determine if any of the demonstration and sample databases, database applications, or files are installed in the database or are included with the MySQL Database Server 8.0 application. If any are present in the database or are included with the MySQL Database Server 8.0 application, this is a finding.

Check database/schema content of MySQL with the following command:
SELECT * FROM information_schema.SCHEMATA where SCHEMA_NAME not in ('mysql','information_schema', 'sys', 'performance_schema');

If this system is identified as production, gather a listing of databases from the server and look for any matching the following general demonstration database names: 
sakila 
world
world_x
menagerie

If any of these databases exist, this is a finding."
  desc 'fix', %q(MySQL 8.0 contains no demo databases by default. If demo schemas (aka databases) were added, remove them by executing:

mysql -u root -p --execute="DROP DATABASE 'schema_name'")
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38362r623549_chk'
  tag severity: 'medium'
  tag gid: 'V-235143'
  tag rid: 'SV-235143r623551_rule'
  tag stig_id: 'MYS8-00-005600'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-38325r623550_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
