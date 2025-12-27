control 'SV-87287' do
  title 'The Cassandra Server must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', 'Obtain document containing the list of approved ports, protocols and services from https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx. Review the Cassandra Server database settings and local documentation for functions, ports, protocols, and services that are not approved. 

Open the console to the server Cassandra DB is hosted at and type: "find / | grep "cassandra.yaml"". Open cassandra.yaml and review "native_transport_port" parameter value. Run "netstat -ntl | grep <"native_transport_port" parameter value >" command from the console on the host.

If protocol, port, and IP address Cassandra communicates on are not found in https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx, this is a finding.'
  desc 'fix', 'Disable functions, ports, protocols, and services that are not part of https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx document, and as such are not approved.

Modify "native_transport_port" and "rpc_address" values in "cassandra.yaml" file, to set them in the approved range (refer to https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx document).'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72655'
  tag rid: 'SV-87287r1_rule'
  tag stig_id: 'VROM-CS-000125'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-79059r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
