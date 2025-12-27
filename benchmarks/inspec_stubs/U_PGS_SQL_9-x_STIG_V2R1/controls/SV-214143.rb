control 'SV-214143' do
  title 'PostgreSQL must protect its audit features from unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator (shown here as "postgres"), verify the permissions of PGDATA: 

$ sudo su - postgres 
$ ls -la ${PGDATA?} 

If PGDATA is not owned by postgres:postgres or if files can be accessed by others, this is a finding. 

As the system administrator, verify the permissions of pgsql shared objects and compiled binaries: 

$ ls -la /usr/pgsql-${PGVER?}/bin
$ ls -la /usr/pgsql-${PGVER?}/include
$ ls -la /usr/pgsql-${PGVER?}/lib
$ ls -la /usr/pgsql-${PGVER?}/share 

If any of these are not owned by root:root, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the system administrator, change the permissions of PGDATA: 

$ sudo chown -R postgres:postgres ${PGDATA?} 
$ sudo chmod 700 ${PGDATA?} 

As the system administrator, change the permissions of pgsql: 

$ sudo chown -R root:root /usr/pgsql-${PGVER?}'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15359r361060_chk'
  tag severity: 'medium'
  tag gid: 'V-214143'
  tag rid: 'SV-214143r508027_rule'
  tag stig_id: 'PGS9-00-011200'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-15357r361061_fix'
  tag 'documentable'
  tag legacy: ['V-73043', 'SV-87695']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
