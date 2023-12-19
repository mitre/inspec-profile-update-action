control 'SV-235146' do
  title 'The MySQL Database Server 8.0 must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems (DBMSs) using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', "Review the MySQL Database Server 8.0 settings and local documentation for functions, ports, protocols, and services that are not approved. If any are found, this is a finding.

Run the following SQL to list ports:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME in ('port', 'mysqlx_port', 'admin_port');

The default ports for MySQL for organizational connects are: 
Classic MySQL - 3306 
MySQL X - 33060
MySQL Admin Port - 33062 (disabled by default)

If any these are in conflict with guidance, and not explained and approved in the system documentation, this is a finding.

Run the following to determine if a local socket/pipe are in use:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where 
VARIABLE_NAME like '%pipe%' or  VARIABLE_NAME = 'socket' or  VARIABLE_NAME = 'mysqlx_socket';

Values for classic and xprotocol will be returned.
For example on Linux:
'socket','/tmp/mysql.sock'
'mysqlx_socket','/tmp/mysqlx.sock'
 Windows
'named_pipe', 'ON'

If these are in conflict with guidance, and not explained and approved in the system documentation, this is a finding."
  desc 'fix', 'Disable functions, ports, protocols, and services that are not approved.

Change mysql options related to network, ports, and protocols for the server and additionally consider refining further at user account level.

vi my.cnf
[mysqld]
port=<port value>
admin_address=<addr>
admin_port=<port value>
mysqlx_port=<port value>
socket={file_name|pipe_name}

If admin_address is not defined then access via the admin port is disabled. 

Additionally the X Plugin can be disabled at startup by either setting mysqlx=0 in the MySQL configuration file, or by passing in either --mysqlx=0 or --skip-mysqlx when starting the MySQL server.
Restart mysqld'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38365r623558_chk'
  tag severity: 'medium'
  tag gid: 'V-235146'
  tag rid: 'SV-235146r638812_rule'
  tag stig_id: 'MYS8-00-006000'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-38328r623559_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
