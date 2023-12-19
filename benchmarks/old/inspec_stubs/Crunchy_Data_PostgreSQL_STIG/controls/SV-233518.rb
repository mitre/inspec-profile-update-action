control 'SV-233518' do
  title 'PostgreSQL must limit privileges to change functions and triggers, and links to software external to PostgreSQL.'
  desc 'If the system were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database code can lead to unauthorized or compromised installations.'
  desc 'check', 'Only owners of objects can change them. To view all functions, triggers, and trigger procedures, their ownership and source, as the database administrator (shown here as "postgres") run the following SQL:

$ sudo su - postgres
$ psql -x -c "\\df+"

Only the OS database owner user (shown here as "postgres") or a PostgreSQL superuser can change links to external software. As the database administrator (shown here as "postgres"), check the permissions of configuration files for the database:

$ sudo su - postgres
$ ls -la ${PGDATA?}

If any files are not owned by the database owner or have permissions allowing others to modify (write) configuration files, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

To change ownership of an object, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER FUNCTION function_name OWNER TO new_role_name"

To change ownership of postgresql.conf, as the database administrator (shown here as "postgres"), run the following commands:

$ sudo su - postgres
$ chown postgres:postgres ${PGDATA?}/postgresql.conf
$ chmod 0600 ${PGDATA?}/postgresql.conf

To remove superuser from a role, as the database administrator (shown here as "postgres"), run the following SQL:

$ sudo su - postgres
$ psql -c "ALTER ROLE rolename WITH NOSUPERUSER"'
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36712r606777_chk'
  tag severity: 'medium'
  tag gid: 'V-233518'
  tag rid: 'SV-233518r606779_rule'
  tag stig_id: 'CD12-00-000710'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-36677r606778_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
