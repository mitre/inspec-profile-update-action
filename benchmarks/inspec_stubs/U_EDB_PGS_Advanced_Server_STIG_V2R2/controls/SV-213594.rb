control 'SV-213594' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

DBMSs may spawn additional external processes to execute procedures that are defined in the DBMS but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than the DBMS and provide unauthorized access to the host system.'
  desc 'check', 'Run the following command as root:  

yum list installed | grep ppas

If any packages are installed that are not needed, this is a finding.'
  desc 'fix', 'Review the EDB PPAS packages available in the installation guide here:

http://www.enterprisedb.com/docs/en/9.5/instguide/Postgres_Plus_Advanced_Server_Installation_Guide.1.14.html#

Uninstall any unneeded packages by running the following as root:

#> yum erase -y <package-name>

At a minimum, the ppas94-server-* packages are required, but other packages such as jdbc, postgis, pgpool and others may be required by applications that need the functionality provided in these additional packages'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14816r290094_chk'
  tag severity: 'medium'
  tag gid: 'V-213594'
  tag rid: 'SV-213594r508024_rule'
  tag stig_id: 'PPS9-00-004000'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-14814r290095_fix'
  tag 'documentable'
  tag legacy: ['SV-83547', 'V-68943']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
