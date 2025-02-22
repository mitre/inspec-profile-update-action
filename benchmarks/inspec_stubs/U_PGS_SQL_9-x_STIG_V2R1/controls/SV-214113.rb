control 'SV-214113' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, PostgreSQL, associated applications, and infrastructure must leverage transmission protection mechanisms.

For more information on configuring PostgreSQL to use SSL, consult the following documentation:
https://www.postgresql.org/docs/current/ssl-tcp.html

Postgres provides native support for using SSL connections to encrypt client/server communications.  To enable the use of SSL, the postgres “ssl” configuration parameter must be set to “on” and the database instance needs to be configured to use a valid server certificate and private key installed on the server.  With SSL enabled, connections made to the database server will default to being encrypted.  However, it is possible for clients to override the default and attempt to establish an unencrypted connection. To prevent connections made from non-local hosts from being unencrypted, the postgres host-based authentication settings should be configured to only allow hostssl (i.e., encrypted) connections.  The hostssl connections can be further configured to require that the client present a valid (trusted) SSL certificate for a connection.'
  desc 'check', ': If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.
First, check if ssl is enabled for the database instance. As the database administrator (shown here as "postgres"), verify SSL is enabled by running the following from a command prompt:

$ sudo su - postgres
$ psql -c "SHOW ssl"

If SSL is not enabled, this is a finding.
Next, open the pg_hba.conf file in a viewer or editor and review the authentication settings that are configured in that file. 

Next, verify hostssl entries in pg_hba.conf: 

$ sudo su - postgres 
$ grep hostssl ${PGDATA?}/pg_hba.conf 

If hostssl entries do not contain clientcert=1, this is a finding. 
If any uncommented lines are not of TYPE "hostssl" and do not include the "clientcert=1" authentication option and are not documented in the system security plan or equivalent document as being approved, this is a finding.
If PostgreSQL does not employ protective measures against unauthorized disclosure and modification during preparation for transmission, this is a finding.'
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

Implement protective measures against unauthorized disclosure and modification during preparation for transmission. 

To configure PostgreSQL to use SSL, as a database administrator (shown here as "postgres"), edit postgresql.conf: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 

Add the following parameter: 

ssl = on 

To change authentication requirements for the database, as the database administrator (shown here as "postgres"), edit pg_hba.conf: 

$ sudo su - postgres 

$ vi ${PGDATA?}/pg_hba.conf 

Edit authentication requirements to the organizational requirements. See the official documentation for the complete list of options for authentication: http://www.postgresql.org/docs/current/static/auth-pg-hba-conf.html 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload 

For more information on configuring PostgreSQL to use SSL, see supplementary content APPENDIX-G.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15329r548750_chk'
  tag severity: 'medium'
  tag gid: 'V-214113'
  tag rid: 'SV-214113r548752_rule'
  tag stig_id: 'PGS9-00-007200'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-15327r548751_fix'
  tag 'documentable'
  tag legacy: ['V-72981', 'SV-87633']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
