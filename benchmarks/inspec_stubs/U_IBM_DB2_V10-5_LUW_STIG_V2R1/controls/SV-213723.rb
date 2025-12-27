control 'SV-213723' do
  title 'DB2 must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

DBMS functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

The DBMS must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization). 

In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.'
  desc 'check', 'The user needs CREATEINAUTH privileges for the schema to create objects in an existing schema.

Run the following Query to find which user has privilege to create objects in schemas:
DB2> SELECT GRANTEE, SCHEMANAME, CREATEINAUTH, ALTERINAUTH 
           FROM SYSCAT.SCHEMAAUTH

If a non-authorized user has privilege, this is a finding.

Run the following query to which user has privilege to create new schema and other objects:
DB2> SELECT GRANTEE, CREATETABAUTH, EXTERNALROUTINEAUTH, DBADMAUTH, IMPLSCHEMAAUTH 
           FROM SYSCAT.DBAUTH

If a non-authorized user has privilege, this is a finding.'
  desc 'fix', 'Run the REVOKE command to revoke database authorities and schema privileges from user: 
DB2> REVOKE CREATEIN ON SCHEMA<schema_name> FROM <user> 
DB2> REVOKE <db authority> ON DATABASE FROM <USER>

Note: Select the following knowledgebase link for information regarding revoking database authorities: 
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0000981.html?cp=SSEPGG_10.5.0%2F2-12-7-181&lang=en

Select the following knowledgebase link for information regarding revoking schema privileges: 
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0000988.html?cp=SSEPGG_10.5.0%2F2-12-7-189&lang=en'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14944r295218_chk'
  tag severity: 'medium'
  tag gid: 'V-213723'
  tag rid: 'SV-213723r879751_rule'
  tag stig_id: 'DB2X-00-008000'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag fix_id: 'F-14942r295219_fix'
  tag 'documentable'
  tag legacy: ['SV-89263', 'V-74589']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
