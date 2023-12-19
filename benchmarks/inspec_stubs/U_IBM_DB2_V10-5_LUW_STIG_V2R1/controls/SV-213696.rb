control 'SV-213696' do
  title 'Unused database components which are integrated in DB2 and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/group permissions.'
  desc 'check', 'Review the system security plan.  Determine what DB2 features are recognized as requiring specific access controls.  Determine which roles are authorized to use and which may not use the designated features.

Review the permissions granted in the database.  If any role is permitted to use any feature not designated as authorized, this is a finding.'
  desc 'fix', 'Use the appropriate version of the REVOKE command to remove unauthorized access to the designated features.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14917r295137_chk'
  tag severity: 'medium'
  tag gid: 'V-213696'
  tag rid: 'SV-213696r879587_rule'
  tag stig_id: 'DB2X-00-003600'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-14915r295138_fix'
  tag 'documentable'
  tag legacy: ['SV-89155', 'V-74481']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
