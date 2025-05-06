control 'SV-89175' do
  title 'DB2 must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', "If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

To protect the confidentiality and integrity of information at rest, the database must be encrypted. DB2 native encryption can encrypt the data at rest; or third-party tools, like IBM Guardium, can provide encryption for data at rest.
 
To find if a database is encrypted with DB2 native encryption, run the following SQL Query:
DB2> SELECT SUBSTR(OBJECT_NAME,1,8) AS NAME, SUBSTR(ALGORITHM,1,8) ALGORITHM 
           FROM TABLE(SYSPROC.ADMIN_GET_ENCRYPTION_INFO()) 
           WHERE OBJECT_TYPE='DATABASE'

If the value of Algorithm is NULL for the database, this is a finding. 

If the database is not encrypted with native encryption or any third-party tool, this is a finding."
  desc 'fix', "To create the database using DB2 native encryption run the following command:

     $db2 create db <database name> encrypt

Note: Select the following link for details on how to set up DB2 native encryption:
http://www-01.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/t0061766.html?lang=en 

If a third-party tool is used for database encryption (IBM highly recommends using IBM Guardium) use the third-party tool's specific check and fix."
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74427r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74501'
  tag rid: 'SV-89175r2_rule'
  tag stig_id: 'DB2X-00-005400'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-81101r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
