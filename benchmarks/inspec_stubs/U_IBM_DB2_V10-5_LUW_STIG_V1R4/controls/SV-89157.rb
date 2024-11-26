control 'SV-89157' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

DBMSs may spawn additional external processes to execute procedures that are defined in the DBMS but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than the DBMS and provide unauthorized access to the host system.'
  desc 'check', "Use the following SQL Query to find external routines: 
DB2> SELECT ROUTINENAME 
           FROM SYSCAT.ROUTINES 
           WHERE ORIGIN='E' 

Use the following command to find out which user has privileges to run the external routines found with last query.
DB2> SELECT GRANTEE 
           FROM SYSCAT.ROUTINEAUTH 

If non-essential routines exist outside the database, this is a finding.

If non-authorized users have privileges on external routines, this is a finding."
  desc 'fix', 'Drop the external routines if these are non-essential for mission objective.
DB2> DROP FUNCTION <name>

Revoke execute privileges from non-authorized users on external routines. 
DB2> REVOKE EXECUTE ON FUNCTION <FUNCTION1> FROM <USER1>

Note: Select the following link for the knowledgebase information on the DROP statement: 
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0000945.html?cp=SSEPGG_10.5.0%2F2-12-7-129&lang=en'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74483'
  tag rid: 'SV-89157r1_rule'
  tag stig_id: 'DB2X-00-003700'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-81083r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
