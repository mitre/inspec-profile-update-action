control 'SV-253693' do
  title 'MariaDB must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or address authorized quality-of-life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', "Review system documentation for a list of approved ports.

As the database administrator, run the following command to determine the currently defined port:
MariaDB>  SHOW GLOBAL VARIABLES LIKE '%port%';
 
If the currently defined port is deemed prohibited, this is a finding."
  desc 'fix', 'Modify the MariaDB configuration file located within /etc/my.cnf.d/ and update the variable port to an acceptable port. Restart MariaDB Enterprise Server. 

Example: 

[server]
port = 4008'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57145r841602_chk'
  tag severity: 'medium'
  tag gid: 'V-253693'
  tag rid: 'SV-253693r841604_rule'
  tag stig_id: 'MADB-10-003500'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-57096r841603_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
