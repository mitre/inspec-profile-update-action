control 'SV-89151' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', 'Use the list db directory to see if the SAMPLE database exists.

     $db2 list db directory

If the SAMPLE database exists, this is a finding.'
  desc 'fix', 'Run the following command to DROP the SAMPLE database:

     $db2 drop database sample'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74403r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74477'
  tag rid: 'SV-89151r1_rule'
  tag stig_id: 'DB2X-00-003400'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-81077r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
