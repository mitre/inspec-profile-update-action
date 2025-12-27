control 'SV-235167' do
  title 'The MySQL Database Server 8.0 must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', "The server must only use approved network communication libraries, ports, and protocols. 

Obtain a list of all approved network libraries, communication ports, and protocols from the server documentation. 

Verify that the protocols are enabled for the instance. 

Run the following SQL to list ports:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME in ('port', 'mysqlx_port', 'admin_port');

The default ports for MySQL for organizational connects are:
Classic MySQL Protocol - 3306, MySQL X Protocol 33060, MySQL Admin Port (disabled by default)

If these are in conflict with guidance, and not explained and approved in the system documentation, this is a finding.

Run the following to determine if a local socker/pipe are in use:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where 
VARIABLE_NAME like '%pipe%' or  VARIABLE_NAME = 'socket' or  VARIABLE_NAME = 'mysqlx_socket';

Values are for classic and xprotocol will be returned.
For example on Linux
'socket','/tmp/mysql.sock'
'mysqlx_socket','/tmp/mysqlx.sock'
 Windows
'named_pipe', 'ON';

If these are in conflict with guidance, and not explained and approved in the system documentation, this is a finding.

Run the following statement to inspect port settings:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE '%port%' or VARIABLE_NAME LIKE '%port' order by  VARIABLE_NAME;

Linux local socket 
select @@socket;

Windows local pipe
select @@named_pipe;

If any ports or protocols are used that are not specifically approved in the server documentation, this is a finding."
  desc 'fix', 'Disable each prohibited network function, port, protocol, or service prohibited by the PPSM guidance.

Change mysql options related to network, ports, and protocols for the server and additionally consider refining further at user account level.

To set ports properly, edit the mysql configuration file and change ports or protocol settings.

vi my.cnf
[mysqld]
port=<port value>
admin_port=<port value>
mysqlx_port=<port value>
socket=/path/to/socket

To turn off TCP/IP:

skip_networking=ON

If admin_address is not defined then access via the admin port is disabled. 

Additionally the X Plugin can be disabled at startup/restart by either setting mysqlx=0 in the MySQL configuration file, or by passing in either "--mysqlx=0" or "--skip-mysqlx" when starting the MySQL server.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38386r623621_chk'
  tag severity: 'medium'
  tag gid: 'V-235167'
  tag rid: 'SV-235167r638812_rule'
  tag stig_id: 'MYS8-00-009000'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-38349r623622_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
