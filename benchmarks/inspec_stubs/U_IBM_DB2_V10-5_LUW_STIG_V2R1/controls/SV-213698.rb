control 'SV-213698' do
  title 'DB2 must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', 'Find out the communication protocol used by running the following command:

$db2set DB2COMM

If DB2 is not set to SSL, this is a finding.

Run the following command to find the service names/port numbers used by the database manager:

$db2 get dbm cfg  

Find the port numbers used by the TCP/IP and SSL services used by database manager (SVCNAME, SSL_SVCENAME) or match the service name in services file to find port numbers.

Default Location for services file

Windows Service File: %SystemRoot%\\system32\\drivers\\etc\\services
UNIX Services File: /etc/services

If ports used by the database manager are nonapproved or deemed unsafe, this is a finding.'
  desc 'fix', 'Run the following command to set the value of the DB2COMM parameter to the organization-approved communication protocol:

     $db2set DB2COMM=TCPIP,SSL

Set the SSL version:

     $db2 update DBM CFG using SSL_VERSIONS TLSV12    

The database manager can be set to a service name or an organization-approved port number directly for the SVCENAME parameter.

Use the following command to change the database manager configuration: 

     $db2 update dbm cfg using svcename <svcename> 
       Or
     $db2 update dbm cfg using svcename <port number>

Note: Configuring Secure Sockets Layer (SSL) support in a DB2 instance:
https://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/t0025241.html'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14919r917660_chk'
  tag severity: 'medium'
  tag gid: 'V-213698'
  tag rid: 'SV-213698r917662_rule'
  tag stig_id: 'DB2X-00-003800'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-14917r917661_fix'
  tag 'documentable'
  tag legacy: ['SV-89159', 'V-74485']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
