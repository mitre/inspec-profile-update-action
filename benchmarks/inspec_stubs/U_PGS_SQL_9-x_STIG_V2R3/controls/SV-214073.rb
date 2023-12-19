control 'SV-214073' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When receiving data, PostgreSQL, associated applications, and infrastructure must leverage protection mechanisms.

For more information on configuring PostgreSQL to use SSL, consult the following documentation:
https://www.postgresql.org/docs/current/ssl-tcp.html

Postgres provides native support for using SSL connections to encrypt client/server communications.  To enable the use of SSL, the postgres “ssl” configuration parameter must be set to “on” and the database instance needs to be configured to use a valid server certificate and private key installed on the server.  With SSL enabled, connections made to the database server will default to being encrypted.  However, it is possible for clients to override the default and attempt to establish an unencrypted connection. To prevent connections made from non-local hosts from being unencrypted, the postgres host-based authentication settings should be configured to only allow hostssl (i.e., encrypted) connections.  The hostssl connections can be further configured to require that the client present a valid (trusted) SSL certificate for a connection.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.
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
If PostgreSQL, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during reception, this is a finding.'
  desc 'fix', 'Implement protective measures against unauthorized disclosure and modification during reception.

To configure PostgreSQL to use SSL, see supplementary content APPENDIX-G for instructions on enabling SSL.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15289r570383_chk'
  tag severity: 'medium'
  tag gid: 'V-214073'
  tag rid: 'SV-214073r548754_rule'
  tag stig_id: 'PGS9-00-003000'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-15287r360851_fix'
  tag 'documentable'
  tag legacy: ['SV-87547', 'V-72895']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
