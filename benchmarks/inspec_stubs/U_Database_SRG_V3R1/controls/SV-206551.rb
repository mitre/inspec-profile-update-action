control 'SV-206551' do
  title 'Unused database components that are integrated in the DBMS and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions.'
  desc 'check', 'Review the DBMS for unused components of the system that cannot be uninstalled.

If unused components or features are present on the system, can be disabled, and are not disabled, this is a finding.'
  desc 'fix', 'Disable any unused components or features that cannot be uninstalled.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6811r291321_chk'
  tag severity: 'medium'
  tag gid: 'V-206551'
  tag rid: 'SV-206551r617447_rule'
  tag stig_id: 'SRG-APP-000141-DB-000092'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6811r291322_fix'
  tag 'documentable'
  tag legacy: ['SV-42763', 'V-32426']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
