control 'SV-89171' do
  title 'DB2 must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator.

However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.'
  desc 'check', 'Ensure DB2 is using the SSL communication protocol:

Run the following command to find the value of the network service:

     $db2 get dbm cfg

TCP/IP Service name                     (SVCENAME) 
SSL service name                         (SSL_SVCENAME) 

If the port numbers are not specified, look for the port numbers in services file and find the port numbers defined for the TCP/IP service name and SSL service name (SVCENAME, SSL_SVCENAME) above.

Default Location for services file:
    Windows Service File:  %SystemRoot%\\system32\\drivers\\etc\\services
    UNIX Services File: /etc/services

If the network protocols and ports found in previous step are not in as per PPSM guidance, this is a finding.'
  desc 'fix', 'Use the following commands to set the protocol and ports as per PPSM guidance:

     $db2 update dbm cfg using svcename    [service_name | port_number]
     $db2 update dbm cfg using ssl_svcename [ssl_service_name | port_number]

Note: http://www.ibm.com/support/knowledgecenter/en/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/t0025241.html'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74423r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74497'
  tag rid: 'SV-89171r1_rule'
  tag stig_id: 'DB2X-00-005100'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-81097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
