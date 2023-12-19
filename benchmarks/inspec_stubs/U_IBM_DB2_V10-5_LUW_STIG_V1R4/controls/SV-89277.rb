control 'SV-89277' do
  title 'DB2 must implement and/or support cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether to employ cryptography is the responsibility of the information owner/steward, who exercises discretion within the framework of applicable rules, policies, and law.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from disclosure; which must include, at a minimum, PII and classified information.

If the documentation indicates no information requires such protections, this is not a finding.

DB2 native encryption can encrypt the data at rest; or third-party tools, like IBM Guardium, can provide encryption for data at rest.
 
To find if a database is encrypted with DB2 native encryption, run the following SQL Query:
DB2> SELECT * FROM TABLE(SYSPROC.ADMIN_GET_ENCRYPTION_INFO())

If the value of Algorithm is NULL for the database, this is a finding. 

If the database is not encrypted with native encryption or any third-party tool, this is a finding.'
  desc 'fix', "To create the database using DB2 native encryption run the following command:

  $db2 create db mydb encrypt

See the detailed instructions in link in the note section below to create the encrypted database.

Note: Select the following link for details on how to set up DB2 native encryption:
http://www-01.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/t0061766.html?lang=en 

If a third-party tool is used for database encryption (IBM highly recommends using IBM Guardium) use the third-party tool's specific check and fix."
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74489r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74603'
  tag rid: 'SV-89277r1_rule'
  tag stig_id: 'DB2X-00-008900'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag fix_id: 'F-81203r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
