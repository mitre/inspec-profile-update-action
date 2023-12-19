control 'SV-224164' do
  title 'The EDB Postgres Advanced Server must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.

A Postgres database cluster (i.e., instance) listens for connections on a single TCP port. The default port for an EDB Postgres Advanced Server cluster is 5444; however, the port number that is used is configurable via the Postgres "port" parameter. A database restart is required to apply a change to the port parameter. Also by default, a Postgres cluster will listen for connections on all interfaces on the host. The "listen_addresses" parameter can be used to configure specific interfaces on the host to listen for connections. The default value of "*" indicates all interfaces are used. To listen only on specific interfaces, the listen_addresses parameter is configured with a comma-separated list of host names and/or numeric IP addresses corresponding to the interfaces that should be used. As with the port parameter, changes to the listen_addresses parameter requires a cluster restart to take effect.'
  desc 'check', 'Review documentation for approved list of ports, protocols, and addresses.

To list the port that is being used, execute the following SQL as enterprisedb:

 SHOW port;

If the port returned by the above command is not approved, this is a finding.

To list the interface addresses that are being used, execute the following SQL as enterprisedb:

 SHOW listen_addresses;

For the above statement, a return value of "*" indicates that the database cluster (i.e., instance) is configured to listen on all interfaces on the database host.

If the addresses returned are not approved, this is a finding.'
  desc 'fix', 'Execute the following SQL as enterprisedb:

 ALTER SYSTEM SET port = <port>;
 ALTER SYSTEM SET listen_addresses = <comma separated addresses>;

Restart the database service. For EDB Postgres Advanced Server, the default service name is "edb-as-<EDB Version #>" with a default display name of "edb-as-<EDB Version #> - Advanced Server <EDB Version #>":

To restart the database service, using the Windows Services Control Manager:
1. Open the Windows Services Control Manager.
2. Select the database service from the list of services, right-click it, and select "Restart".

Alternatively, the database can be restarted via the Windows command line using either the NET or SC command as follows:

 NET STOP <service name>
 NET START <service name>

or

 SC STOP <service name>
 SC START <service name>

Note that if pgAgent is installed and running, the corresponding pgAgent service is dependent on the EDB Postgres database service and will first need to be stopped in order to restart the database service. After restarting the database service, the pgAgent service may be started again.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25837r495510_chk'
  tag severity: 'medium'
  tag gid: 'V-224164'
  tag rid: 'SV-224164r508023_rule'
  tag stig_id: 'EP11-00-004100'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-25825r495511_fix'
  tag 'documentable'
  tag legacy: ['SV-109459', 'V-100355']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
