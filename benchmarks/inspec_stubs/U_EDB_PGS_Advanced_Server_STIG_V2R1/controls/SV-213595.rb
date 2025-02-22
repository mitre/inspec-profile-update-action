control 'SV-213595' do
  title 'The EDB Postgres Advanced Server must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW port;
SHOW listen_addresses;
 
If the port or addresses are not approved, this is a finding.'
  desc 'fix', 'Execute the following SQL as enterprisedb:

ALTER SYSTEM SET port = <port>;
ALTER SYSTEM SET listen_addresses = <comma separated addresses>;

Execute the following operating system command as root:

systemctl restart ppas-9.5.service'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14817r290097_chk'
  tag severity: 'medium'
  tag gid: 'V-213595'
  tag rid: 'SV-213595r508024_rule'
  tag stig_id: 'PPS9-00-004100'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-14815r290098_fix'
  tag 'documentable'
  tag legacy: ['V-68945', 'SV-83549']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
