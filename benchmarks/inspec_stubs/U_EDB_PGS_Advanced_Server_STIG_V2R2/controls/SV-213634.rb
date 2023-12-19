control 'SV-213634' do
  title 'The EDB Postgres Advanced Server must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When receiving data, the DBMS, associated applications, and infrastructure must leverage protection mechanisms.

EDB Postgres Advanced Server provides native support for using SSL connections to encrypt client/server communications. To enable the use of SSL, the postgres “ssl” configuration parameter must be set to “on” and the database instance needs to be configured to use a valid server certificate and private key installed on the server. With SSL enabled, connections made to the database server will default to being encrypted. However, it is possible for clients to override the default and attempt to establish an unencrypted connection. To prevent connections made from non-local hosts from being unencrypted, the postgres host-based authentication settings should be configured to only allow hostssl (i.e., encrypted) connections. The hostssl connections can be further configured to require that the client present a valid (trusted) SSL certificate for a connection.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

First, check if SSL is enabled for the database instance by executing the following command from a command prompt:
   psql -d <database name> -U <database superuser name> -c "SHOW ssl”
Where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).
If the result is not "on", this is a finding. 
Next, open the pg_hba.conf file in a viewer or editor and review the authentication settings that are configured in that file. 

Note the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running EDB postgres instance can be found using the following command run from a command prompt:
   psql -d <database name> -U <database superuser name> -c "SHOW hba_file" 
Where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS). 

If any uncommented lines are not of TYPE "hostssl" and do not include the "clientcert=1" authentication option and are not documented in the system security plan or equivalent document as being approved, this is a finding.'
  desc 'fix', 'To configure EDB Postgres Advanced Server to use SSL, open the ”postgresql.conf" file in an editor. Note the default location for the postgresql.conf file is in the postgresql data directory.  The location of the postgresql.conf for a running EDB Postgres instance can be found using the following command run from a command prompt:

   psql -d <database name> -U <database superuser name> -c “SHOW config_file”

Where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

In the postgresql.conf file, set the “ssl” parameter as follows:

   ssl = on

Make sure the parameter is uncommented. 

In order to start an EDB Postgres Advanced Server instance in SSL mode, files containing the server certificate and private key must exist. By default, these files are expected to exist in the Postgres data directory and are expected to be named server.crt and server.key, respectively. Update the ssl_cert_file and ssl_cert_key parameters in the postgresql.conf file if the files are placed in a different location or are named differently. 
Note that changes to the SSL parameter setting and any of the other SSL- related parameters require a database server restart to be put the changes into effect. 
To restart the database on a systemd server, issue the following command as the root user or a user with sudo access:
   systemctl restart edb-as-<EPAS version>
Where, “<EPAS version>” is the major version of the EDB Postgres Advanced Server instance (e.g., 9.6).

To restart the database on an initd server, issue the following command as the root user or a user with sudo access:
   service edb-as-<EDB Postgres version> restart
Where, “<EPAS version>” is the major version of the EDB Postgres Advanced Server instance (e.g., 9.6).
After verifying that SSL is enabled for the database, open the pg_hba.conf file in an editor to configure the host-based authentication settings. Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running EDB postgres instance can be found using the following command run from a command prompt:
   psql -d <database name> -U <database superuser name> -c "SHOW hba_file" 
Where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

Obtain approval and document any uncommented entries with corresponding justification that are not of type hostssl and do not include the “clientcert=1” option.

For any entries that are not of type hostssl authentication with the “clientcert=1” option and not documented and approved, change the "TYPE" column to “hostssl” and add the “clientcert=1” authentication method option. 

Note that changes to the host-based authentication settings require a database reload in order to apply the updated settings.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14856r570387_chk'
  tag severity: 'medium'
  tag gid: 'V-213634'
  tag rid: 'SV-213634r557397_rule'
  tag stig_id: 'PPS9-00-009600'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-14854r570388_fix'
  tag 'documentable'
  tag legacy: ['SV-83625', 'V-69021']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
