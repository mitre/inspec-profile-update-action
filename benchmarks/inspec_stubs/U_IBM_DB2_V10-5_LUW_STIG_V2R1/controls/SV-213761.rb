control 'SV-213761' do
  title 'DB2 must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to the DBMS that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and non-standard sources.'
  desc 'check', "Run the following SQL statement to ensure that an audit policy is defined upon the database: 
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
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES VALIDATE STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14982r295332_chk'
  tag severity: 'medium'
  tag gid: 'V-213761'
  tag rid: 'SV-213761r879879_rule'
  tag stig_id: 'DB2X-00-012200'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-14980r295333_fix'
  tag 'documentable'
  tag legacy: ['SV-89251', 'V-74577']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
