control 'SV-89279' do
  title 'DB2 must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', 'The DB2 database system supports the use of Transport Layer Security (TLS) to enable a client to authenticate a server and to provide private communication between the client and server by use of encryption. 

Run the following command to find out what versions of TLS are supported by the server:

$db2 get dbm cfg 

If the value of the ssl_versions parameter is not set to "TLSV1" or "TLSV12" this is a finding.

Check the value of the DB2COMM parameter using the following command:

$db2set –all 

If the value of DB2COMM is not set to "SSL", this is a finding. 

Note: When this topic mentions SSL, the same information applies to TLS, unless otherwise noted.'
  desc 'fix', 'Run the following DB2 command to set the value of ssl_versions to approved TLS or SSL version: 

$db2 update dbm cfg using SSL_VERSIONS <SSL Version>

Run the following command to set the value of db2comm parameter to SSL: 

$db2set db2comm=ssl

Restart the database manager.

Note: Details on key database creation and setting up SSL environment are in following links

Select the following knowledgebase link for more information regarding configuring SSL support:
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/t0025241.html?lang=en

Select the following knowledgebase link for more information regarding SSL_versions:
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.config.doc/doc/r0053616.html?cp=SSEPGG_10.5.0%2F2-4-4-8-88&lang=en

Select the following knowledgebase link for setting communication protocol:
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.qb.server.doc/doc/t0004714.html?cp=SSEPGG_10.5.0&lang=en'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74491r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74605'
  tag rid: 'SV-89279r2_rule'
  tag stig_id: 'DB2X-00-009100'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-81205r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
