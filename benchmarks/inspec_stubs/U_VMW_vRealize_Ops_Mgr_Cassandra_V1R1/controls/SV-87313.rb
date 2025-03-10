control 'SV-87313' do
  title 'The Cassandra Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', 'Review the Cassandra Server to ensure network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accordance with the Ports, Protocols, and Services Management (PPSM) guidance are disabled.

Open the console to the server that Cassandra DB is hosted at and type: "find / | grep "cassandra.yaml"". Open "cassandra.yaml" file and review "start_rpc", "start_native_transport", and "native_transport_port" parameters values.

If "start_rpc" is not set to "false" and "start_native_transport" is not set to "true", this is a finding.

Run following command from the console of server, hosting Cassandra: "netstat -ntl | grep <native_transport_port > parameter value". Review output of this command record for the protocol and port Cassandra listens at.

Obtain the document containing the list of approved ports, protocols, and services from https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx.

If protocol and port Cassandra listens at are not approved, this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accordance with the Ports, Protocols, and Services Management (PPSM) guidance.

Open the console to the server that Cassandra DB is hosted at and type: "find / | grep "cassandra.yaml"". Open "cassandra.yaml" file and modify "start_rpc parameter" value to "false", "start_native_transport parameter" value to "true" and "native_transport_port" parameter value to one in the range of approved ports, according to https://disa.deps.mil/ext/cop/iase/ppsm/Pages/cal.aspx document (default port is 9042).'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72681'
  tag rid: 'SV-87313r1_rule'
  tag stig_id: 'VROM-CS-000240'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-79085r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
