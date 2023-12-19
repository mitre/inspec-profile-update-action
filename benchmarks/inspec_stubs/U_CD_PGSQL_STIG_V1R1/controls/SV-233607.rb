control 'SV-233607' do
  title 'PostgreSQL must protect its audit features from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER, and APPENDIX-I for PGLOG. Only the database owner and superuser can alter configuration of PostgreSQL.

Ensure the PGLOG directory is owned by postgres user and group:

$ sudo su - postgres
$ ls -la ${PGLOG?} 

If PGLOG is not owned by the database owner, this is a finding. 

Ensure the data directory is owned by postgres user and group. 

$ sudo su - postgres
$ ls -la ${PGDATA?}

If PGDATA is not owned by the database owner, this is a finding.

Ensure pgaudit installation is owned by root:

$ sudo su - postgres
$ ls -la /usr/pgsql-${PGVER?}/share/contrib/pgaudit

If pgaudit installation is not owned by root, this is a finding.

Next, as the database administrator (shown here as "postgres"), run the following SQL to list all roles and their privileges:

$ sudo su - postgres
$ psql -x -c "\\du"

If any role has "superuser" that should not, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER and APPENDIX-I for PGLOG.

If PGLOG or PGDATA are not owned by postgres user and group, configure them as follows: 

$ sudo chown -R postgres:postgres ${PGDATA?}
$ sudo chown -R postgres:postgres ${PGLOG?}

If the pgaudit installation is not owned by root user and group, configure it as follows:

$ sudo chown -R root:root /usr/pgsql-${PGVER?}/share/contrib/pgaudit

To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER ROLE <role-name> WITH NOSUPERUSER"'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36801r607044_chk'
  tag severity: 'medium'
  tag gid: 'V-233607'
  tag rid: 'SV-233607r617333_rule'
  tag stig_id: 'CD12-00-010700'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-36766r607045_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
