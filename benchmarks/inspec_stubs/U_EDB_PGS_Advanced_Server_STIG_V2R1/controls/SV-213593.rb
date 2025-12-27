control 'SV-213593' do
  title 'Unused database components which are integrated in the EDB Postgres Advanced Server and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/group permissions.'
  desc 'check', 'Run the following command as root:  

yum list installed | grep ppas

If any packages are installed that are not needed, this is a finding.'
  desc 'fix', 'Review the EDB PPAS packages available in the installation guide here:

http://www.enterprisedb.com/docs/en/9.5/instguide/Postgres_Plus_Advanced_Server_Installation_Guide.1.14.html#

Uninstall any unneeded packages by running the following as root:

yum erase -y <package-name>

At a minimum, the ppas94-server-* packages are required, but other packages such as jdbc, postgis, pgpool and others may be required by applications that need the functionality provided in these additional packages'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14815r290091_chk'
  tag severity: 'medium'
  tag gid: 'V-213593'
  tag rid: 'SV-213593r508024_rule'
  tag stig_id: 'PPS9-00-003900'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-14813r290092_fix'
  tag 'documentable'
  tag legacy: ['V-68941', 'SV-83545']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
