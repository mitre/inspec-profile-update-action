control 'SV-253690' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding-specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', 'As the database administrator, show all databases by running the following SQL:

MariaDB> SHOW DATABASES;

Determine if the test database still exists. If it does, this is a finding.'
  desc 'fix', %q(If a test database is found, this is a sign that the mysql_secure_installation script was not ran when the database software was installed. It is recommended to do so. This script will prompt the user to set the MariaDB root user's password, remove all anonymous users, disallow the root user from logging in remotely to the database, remove the test database and access to it, and then reload the privilege tables.
 
$ mariadb-secure-installation
 
reply Y to setting a root password if one is not already set.
 
reply Y to Remove anonymous users

reply Y to disallow root login remotely
 
reply Y to Remove test database and access to it
 
reply Y to Reload privilege tables now (this ensures that all changes made so far will take effect immediately)
 
Note: For this request only the "reply Y to Remove" test database and access to it is necessary, but "Y" to all the questions is recommended.

Alternatively, simply dropping the test database will remedy the finding. 

MariaDB> DROP DATABASE test;)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57142r841593_chk'
  tag severity: 'medium'
  tag gid: 'V-253690'
  tag rid: 'SV-253690r841595_rule'
  tag stig_id: 'MADB-10-003100'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-57093r841594_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
