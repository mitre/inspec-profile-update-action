control 'SV-213753' do
  title 'DB2 must generate audit records when successful logons or connections occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to the DBMS.'
  desc 'check', "To meet these requirements at the VALIDATE, CONTEXT category auditing needs to be implemented at database level. 

Run the following SQL statement to ensure that an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ')

If no rows are returned, this is a finding. 

Using the AUDITPOLICYID from above query find the details of audit policy: 
DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, VALIDATESTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for CONTEXTSTATUS and VALIDATESTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <audit policy name> 
           CATEGORIES VALIDATE STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14974r295308_chk'
  tag severity: 'medium'
  tag gid: 'V-213753'
  tag rid: 'SV-213753r879874_rule'
  tag stig_id: 'DB2X-00-011400'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-14972r295309_fix'
  tag 'documentable'
  tag legacy: ['SV-89321', 'V-74647']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
