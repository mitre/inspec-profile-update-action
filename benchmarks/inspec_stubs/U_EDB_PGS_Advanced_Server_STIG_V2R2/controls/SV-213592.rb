control 'SV-213592' do
  title 'Unused database components, EDB Postgres Advanced Server software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'Review the list of components and features installed with the database. 

If unused components are installed and are not documented and authorized, this is a finding. 

RPM can also be used to check to see what is installed: 

yum list installed | grep ppas

This returns EDB database packages that have been installed. If any packages displayed by this command are not being used, this is a finding.'
  desc 'fix', 'If any components are required for operation of applications that will be accessing the DBMS, include them in the system documentation. 

To uninstall and unused package (using ppas-odbc-devel-09.03.0400.02-1.rhel7.x86_64 as an example), execute the following command as root:

yum erase -y ppas-odbc-devel-09.03.0400.02-1.rhel7.x86_64'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14814r290088_chk'
  tag severity: 'medium'
  tag gid: 'V-213592'
  tag rid: 'SV-213592r508024_rule'
  tag stig_id: 'PPS9-00-003800'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-14812r290089_fix'
  tag 'documentable'
  tag legacy: ['SV-83543', 'V-68939']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
