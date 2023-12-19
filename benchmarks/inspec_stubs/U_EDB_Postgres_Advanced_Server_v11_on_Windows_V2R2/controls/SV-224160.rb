control 'SV-224160' do
  title 'Default, demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', "If EDB Postgres Advanced Server (EPAS) is hosted on a server that does not support production systems, and is designated for the deployment of samples and demonstrations, this is not applicable (NA).

Review documentation and websites from EnterpriseDB and any other relevant vendors for vendor-provided demonstration or sample databases, database applications, schemas, objects, and files.

Review the EPAS DBMS to determine if any of the demonstration and sample databases, schemas, database applications, or objects are installed in the database or are included with the DBMS application. If any are present in the database or are included with the DBMS application, this is a finding.

Check for the existence of EDB Postgres sample databases: postgres and edb. To check Execute the following SQL as enterprisedb:

 SELECT datname FROM pg_database WHERE datistemplate = false;

If any databases are listed here that are not documented as being used by the application, this is a finding.

EDB Postgres provides the ability to install a set of sample tables and related objects in a postgres database via the installer or via the edb-sample.sql script installed with EDB Postgres Advanced Server (located in the <EDB Postgres Installation Directory>\\installer\\server directory by default). To check whether these sample tables have been installed, execute the following SQL as enterprisedb: 

 SELECT * FROM dba_tables WHERE table_name IN ('EMP', 'DEPT', 'JOBHIST');

If any rows are returned that do not correspond to application tables, this is a finding.

Postgres provides the ability to install a set of tables for benchmark purposes using the pgbench utility. To check whether these pgbench tables have been installed, execute the following SQL as enterprisedb:

 SELECT * FROM dba_tables WHERE table_name LIKE 'PGBENCH%';

If any rows are returned that do not correspond to application tables, this is a finding."
  desc 'fix', 'Remove any unused sample databases or sample objects within a database from the DBMS.

To remove a database, execute the follow SQL:

 DROP DATABASE <database>;

To remove objects within a database, use the appropriate DROP statement (DROP TABLE, DROP VIEW, etc.).'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25833r495498_chk'
  tag severity: 'medium'
  tag gid: 'V-224160'
  tag rid: 'SV-224160r508023_rule'
  tag stig_id: 'EP11-00-003700'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-25821r495499_fix'
  tag 'documentable'
  tag legacy: ['SV-109451', 'V-100347']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
