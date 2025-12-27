control 'SV-96573' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'Review the list of components and features installed with the MongoDB database. 

If unused components are installed and are not documented and authorized, this is a finding. 

RPM can also be used to check to see what is installed: 

yum list installed | grep mongodb

This returns MongoDB database packages that have been installed. 

If any packages displayed by this command are not being used, this is a finding.'
  desc 'fix', 'On data-bearing nodes and arbiter nodes, the mongodb-enterprise-tools, mongodb-enterprise-shell and mongodb-enterprise-mongos can be removed (or not installed).

On applications servers that typically run the mongos process when connecting to a shared cluster, the only package required is the mongodb-enterprise-mongos package.'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81651r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81859'
  tag rid: 'SV-96573r1_rule'
  tag stig_id: 'MD3X-00-000280'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-88709r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
