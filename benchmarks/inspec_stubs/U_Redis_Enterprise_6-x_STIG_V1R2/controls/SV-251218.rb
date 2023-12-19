control 'SV-251218' do
  title 'Unused database components that are integrated in Redis Enterprise DBMS and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions.'
  desc 'check', 'Redis Enterprise comes with a suite of capabilities sorted into modules. These modules can be removed if deemed unnecessary. Check the installed modules in the UI at the following location:
1. Log in to the Redis Enterprise UI as an Admin user.
2. Navigate to the Settings tab.
3. View the Redis Modules tab.

If unused components or features are present on the system, can be disabled, and are not disabled, this is a finding.'
  desc 'fix', 'To view/remove installed modules from the UI:
1. Click "Settings" in the red banner.
2. Click Redis modules.
3. Find the module to be removed and click the trash can icon on the right.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54653r804842_chk'
  tag severity: 'medium'
  tag gid: 'V-251218'
  tag rid: 'SV-251218r804844_rule'
  tag stig_id: 'RD6X-00-008200'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-54607r804843_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
