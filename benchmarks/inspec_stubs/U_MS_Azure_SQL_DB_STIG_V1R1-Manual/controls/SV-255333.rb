control 'SV-255333' do
  title 'Azure SQL Database default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled.

Azure SQL Database must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the Azure SQL Database.'
  desc 'check', 'Review vendor documentation and vendor websites to identify vendor-provided demonstration or sample databases, database applications, objects, and files. 

Review the Azure SQL Database to determine if any of the demonstration and sample databases, database applications, or files are installed in the database or are included with the Azure SQL Database.

If any are present in the database or are included with the Azure SQL Database, this is a finding.'
  desc 'fix', 'Remove any demonstration and sample databases, database applications, objects, and files from the Azure SQL Database.

Drop Database Syntax: https://docs.microsoft.com/en-us/sql/t-sql/statements/drop-database-transact-sql?view=azuresqldb-current'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59006r873661_chk'
  tag severity: 'medium'
  tag gid: 'V-255333'
  tag rid: 'SV-255333r877268_rule'
  tag stig_id: 'ASQL-00-006900'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-58950r877267_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
