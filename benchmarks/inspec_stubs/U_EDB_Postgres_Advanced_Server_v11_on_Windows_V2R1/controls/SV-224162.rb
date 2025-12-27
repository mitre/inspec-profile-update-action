control 'SV-224162' do
  title 'Unused database components which are integrated in the EDB Postgres Advanced Server and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component, and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions.'
  desc 'check', 'Open Control Program >> Programs >> Programs and Features. Look specifically for publishers of EnterpriseDB, pgAdmin, or PostgreSQL. If any programs are installed which are not documented as needed by the government program, this is a finding.'
  desc 'fix', 'Open Control Program >> Programs >> Programs and Features. Select any programs that should not be installed, click "uninstall", and then follow the prompts to uninstall the software.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25835r495504_chk'
  tag severity: 'medium'
  tag gid: 'V-224162'
  tag rid: 'SV-224162r508023_rule'
  tag stig_id: 'EP11-00-003900'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-25823r495505_fix'
  tag 'documentable'
  tag legacy: ['SV-109455', 'V-100351']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
