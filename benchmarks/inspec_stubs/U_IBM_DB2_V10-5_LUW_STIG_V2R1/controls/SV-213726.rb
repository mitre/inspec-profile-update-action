control 'SV-213726' do
  title 'DB2 must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', 'Run the following command to find the value of the network service:

     $db2 get dbm cfg

TCP/IP Service name                     (SVCENAME) 
SSL service name                         (SSL_SVCENAME) 

If the port numbers are not specified, look for the port numbers in services file and find the port numbers defined for the TCP/IP service name and SSL service name (SVCENAME, SSL_SVCENAME) above.

Default Location for services file:
   Windows Service File:  %SystemRoot%\\system32\\drivers\\etc\\services
   UNIX Services File: /etc/services

If the network protocols and ports found in previous step are not in as per PPSM guidance, this is a finding.'
  desc 'fix', 'Use the following commands to set the protocol and ports as per PPSM guidance:

     $db2 update dbm cfg using svcename [service_name | port_number]

     $db2 update dbm cfg using ssl_svcename [ssl_service_name | port_number]


Note: http://www.ibm.com/support/knowledgecenter/en/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/t0025241.html'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14947r295227_chk'
  tag severity: 'medium'
  tag gid: 'V-213726'
  tag rid: 'SV-213726r879756_rule'
  tag stig_id: 'DB2X-00-008300'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-14945r295228_fix'
  tag 'documentable'
  tag legacy: ['SV-89269', 'V-74595']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
