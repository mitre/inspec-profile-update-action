control 'SV-224208' do
  title 'The EDB Postgres Advanced Server must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.

EDB Postgres Advanced Server provides native support for using SSL connections to encrypt client/server communications. To enable the use of SSL, the postgres “ssl” configuration parameter must be set to “on” and the database instance needs to be configured to use a valid server certificate and private key installed on the server. With SSL enabled, connections made to the database server will default to being encrypted. However, it is possible for clients to override the default and attempt to establish an unencrypted connection. To prevent connections made from non-local hosts from being unencrypted, the postgres host-based authentication settings should be configured to only allow hostssl (i.e., encrypted) connections. The hostssl connections can be further configured to require the client present a valid (trusted) SSL certificate for a connection.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.
First, check if SSL is enabled for the database instance by connecting to the database as a database superuser using psql and executing the following command:
    SHOW ssl;
If the result is not "on", this is a finding. 
Next, review the host based authentication settings by connecting to the database as a database superuser using psql and executing the following command:
   SELECT * FROM pg_hba_file_rules;
Alternatively, open the pg_hba.conf file in a viewer or editor and review the authentication settings that are configured in that file. 

Note the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running EDB postgres instance can be found by connecting to the database as a database superuser using psql and executing the following command:
   SHOW hba_file; 

If any uncommented lines are not of TYPE "hostssl" and do not include the "clientcert=1" authentication option and are not documented in the system security plan or equivalent document as being approved, this is a finding.'
  desc 'fix', 'To configure EDB Postgres Advanced Server to use SSL, open the ”postgresql.conf" file in an editor. Note the default location for the postgresql.conf file is in the postgresql data directory. The location of the postgresql.conf for a running EDB Postgres instance can be found by connecting to the database as a database superuser using psql and executing the following command:

   SHOW config_file;

In the postgresql.conf file, set the “ssl” parameter as follows:

   ssl = on

Make sure the parameter is uncommented. 

In order to start an EDB Postgres Advance Server instance in SSL mode, files containing the server certificate and private key must exist. By default, these files are expected to exist in the Postgres data directory and are expected to be named server.crt and server.key, respectively. Update the ssl_cert_file and ssl_cert_key parameters in the postgresql.conf file if the files are placed in a different location or are named differently. 
Note that changes to the ssl parameter setting and any of the other ssl related parameters require a reload of the database server configuration to put the changes into effect. 
To reload the database server configuration, connect to the database as a database superuser using psql and execute the following command:
   SELECT pg_reload_conf();
After verifying that SSL is enabled for the database, open the pg_hba.conf file in an editor to configure the host-based authentication settings. Note the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running EDB postgres instance can be found by connecting to the database as a database superuser using psql and execute the following command:
   SHOW hba_file;

Obtain approval and document any uncommented entries with corresponding justification that are not of type hostssl and do not include the “clientcert=1” option.

For any entries that are not of type hostssl authentication with the “clientcert=1” option and not documented and approved, change the "TYPE" column to “hostssl” and add the “clientcert=1” authentication method option. 

Note on Microsoft Windows systems, changes to the host-based authentication settings in the pg_hba.conf file are immediately applied by subsequent new connections.

For more information on configuring PostgreSQL to use SSL, consult the following documentation:
https://www.postgresql.org/docs/current/ssl-tcp.html

For more information on configuring the postgresql pg_hba.conf file, consult the following documentation:
https://www.postgresql.org/docs/current/auth-pg-hba-conf.html'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25881r570389_chk'
  tag severity: 'medium'
  tag gid: 'V-224208'
  tag rid: 'SV-224208r557402_rule'
  tag stig_id: 'EP11-00-009500'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-25869r570390_fix'
  tag 'documentable'
  tag legacy: ['SV-109541', 'V-100437']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
