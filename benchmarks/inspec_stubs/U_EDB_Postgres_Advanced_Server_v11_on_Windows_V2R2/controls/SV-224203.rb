control 'SV-224203' do
  title 'The EDB Postgres Advanced Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.

A database cluster listens on a single port (usually 5444 for Postgres Plus Advanced Server). The Postgres Enterprise Manager (PEM) agents do not listen on ports, they only act as clients to the PEM server. The PEM server has two components (a repository which is a Postgres database) and an Apache HTTPD application. The Apache HTTPD application listens on a port configured in Apache, generally 8080 or 8443.

The ports to check are: 
1) The primary Postgres cluster port, 
2) If PEM is in use, the PEM Apache HTTPD port, and 
3) The PEM Repository DB port. 

Generally 2 and 3 should be installed on an isolated management machine without access from anyone other than administrators.'
  desc 'check', 'Review the network functions, ports, protocols, and services supported by the DBMS.

If any protocol is prohibited by the PPSM guidance and is enabled, this is a finding.

Open the pg_hba.conf file in an editor and verify that none of the uncommented rows have a TYPE of "host" or "hostnossl". 

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

If any rows in the pg_hba.conf file have a TYPE that is "host" or "hostnossl" and not documented as approved in the system security documentation, this is a finding.

Execute the following SQL as enterprisedb:

 SHOW port;

If the displayed port is not allowed, this is a finding.'
  desc 'fix', 'Disable each prohibited network function, port, protocol, or service prohibited by the PPSM guidance.

Open the pg_hba.conf file in an editor and change the TYPE of any rows not starting with a "#" to be "hostssl". The METHOD for the hostssl rows should be one of these (in preferred order): cert, sspi, ldap, scram-sha-256

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

Execute the following SQL as enterprisedb:

 ALTER SYSTEM SET port = <port>;

Restart the database service. For EDB Postgres Advanced Server, the default service name for an instance will be "edb-as-<version>" with a default display name of "edb-as-<version> - Advanced Server <version>", where "<version>" is the major version number of the EDB Postgres Advanced Server that is installed:

To restart the database service, using the Windows Services Control Manager:
 1. Open the Windows Services Control Manager.
 2. Select the database service from the list of services, right-click it, and select "Restart".

Alternatively, the database can be restarted via the Windows command line using either the NET or SC command as follows:

 NET STOP <service name>
 NET START <service name>

or

 SC STOP <service name>
 SC START <service name>

In the above commands, replace <service name> with the actual service name corresponding to the EDB Postgres instance.

Note that if pgAgent is installed and running, the corresponding pgAgent service is dependent on the EDB Postgres database service and must first be stopped to restart the database service. After restarting the database service, the pgAgent service may be started again.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25876r495627_chk'
  tag severity: 'medium'
  tag gid: 'V-224203'
  tag rid: 'SV-224203r508023_rule'
  tag stig_id: 'EP11-00-008700'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-25864r495628_fix'
  tag 'documentable'
  tag legacy: ['SV-109531', 'V-100427']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
