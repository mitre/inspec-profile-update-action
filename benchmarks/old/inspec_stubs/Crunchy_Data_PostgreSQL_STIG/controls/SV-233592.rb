control 'SV-233592' do
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
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36786r606999_chk'
  tag severity: 'medium'
  tag gid: 'V-233592'
  tag rid: 'SV-233592r607001_rule'
  tag stig_id: 'CD12-00-008900'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-36751r607000_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
