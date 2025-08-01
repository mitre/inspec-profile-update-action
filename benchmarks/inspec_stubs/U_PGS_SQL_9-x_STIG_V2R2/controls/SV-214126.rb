control 'SV-214126' do
  title 'Unused database components, PostgreSQL software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.  

PostgreSQL must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', %q(To get a list of all extensions installed, use the following commands: 

$ sudo su - postgres 
$ psql -c "select * from pg_extension where extname != 'plpgsql'" 

If any extensions exist that are not approved, this is a finding.)
  desc 'fix', 'To remove extensions, use the following commands:

$ sudo su - postgres
$ psql -c "DROP EXTENSION <extension_name>"

Note: It is recommended that plpgsql not be removed.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15342r361009_chk'
  tag severity: 'medium'
  tag gid: 'V-214126'
  tag rid: 'SV-214126r508027_rule'
  tag stig_id: 'PGS9-00-008900'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-15340r361010_fix'
  tag 'documentable'
  tag legacy: ['SV-87659', 'V-73007']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
