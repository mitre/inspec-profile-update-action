control 'SV-213676' do
  title 'DB2 must generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.'
  desc 'check', "To monitor who/what is reading the privilege/permission/role information from catalog tables a minimum audit set of CONTEXT and EXECUTE (with data) categories on the following catalog tables are required:

SYSIBM.SYSINDEXAUTH
SYSIBM.SYSPLANAUTH
SYSIBM.SYSPASSTHRUAUTH
SYSIBM.SYSROUTINEAUTH
SYSIBM.SYSSCHEMAAUTH
SYSIBM.SYSSECURITYLABELACCESS
SYSIBM.SYSSECURITYPOLICYEXEMPTIONS
SYSIBM.SYSSEQUENCEAUTH
SYSIBM.SYSSURROGATEAUTHIDS
SYSIBM.SYSTABAUTH 
SYSIBM.SYSTBSPACEAUTH 
SYSIBM.SYSXSROBJECTAUTH
SYSIBM.SYSCOLAUTH
SYSIBM.SYSLIBRARYAUTH
SYSIBM.SYSMODULEAUTH
SYSIBM.SYSROLEAUTH
SYSIBM.SYSVARIABLEAUTH
SYSIBM.SYSWORKLOADAUTH
SYSIBM.SYSDBAUTH
SYSIBM.SYSUSERAUTH

Run the following SQL statement to ensure that an audit policy is defined upon the above catalog tables and/or the database:

DB2> SELECT AUDITPOLICYNAME, OBJECTSCHEMA, OBJECTNAME, OBJECTTYPE 
FROM SYSCAT.AUDITUSE 
WHERE OBJECTTYPE IN ('T',' ')

If no rows are returned, this is a finding. 

If a row with the OBJECTTYPE of ' ' (Database; value is a blank) exists in the output, it is a database level policy. 

If a row with OBJECTTYPE of 'T' exists in the output, it is a table level policy.

For each audit policy returned in the statement above, run the following SQL statement to confirm that the CONTEXT and EXECUTE categories are part of that policy:

DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, EXECUTESTATUS, ERRORTYPE AS ERRORTYPE 
FROM SYSCAT.AUDITPOLICIES

If the values for CONTEXTSTATUS and EXECUTESTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding.

If a database policy does not exist or does not cover CONTEXTSTATUS or EXECUTESTATUS then check if the appropriate policies are defined for all the required tables listed above.

If audit policies for the required tables do not have the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'S' (Success) or 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Define the audit policy using the CREATE AUDIT POLICY SQL statement:
DB2> CREATE AUDIT POLICY CATALOGAUDIT CATEGORIES CONTEXT STATUS BOTH, EXECUTE STATUS BOTH ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, apply the correct audit policy to either the database as a whole or to the specific catalog tables using one of these two statements:
DB2> AUDIT DATABASE USING POLICY CATALOGAUDIT 
  Or 
DB2> AUDIT TABLE <table name> USING POLICY CATALOGAUDIT

Note: The Database level policy in the Check category, covered in SRG-DB2X-00-000600, generates audit events of successful/unsuccessful read attempts on views based on these catalog tables.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14897r295077_chk'
  tag severity: 'medium'
  tag gid: 'V-213676'
  tag rid: 'SV-213676r879561_rule'
  tag stig_id: 'DB2X-00-000800'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-14895r295078_fix'
  tag 'documentable'
  tag legacy: ['SV-89115', 'V-74441']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
