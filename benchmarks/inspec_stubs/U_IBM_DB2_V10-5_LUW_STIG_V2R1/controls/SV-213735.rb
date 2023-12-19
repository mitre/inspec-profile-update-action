control 'SV-213735' do
  title 'DB2 must generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked.

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality.

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', "To ensure the database generates audit records when security objects are accessed the following audit categories must be implemented at the database level: 

AUDIT
CHECKING
CONTEXT
SECMAINT
SYSADMIN
VALIDATE 

Run the following SQL statement to determine if an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ')

If no rows are returned, this is a finding. 

Using the AUDITPOLICYID returned from above query, run the following command to find the details of audit policy: 
DB2> SELECT AUDITPOLICYNAME, AUDITSTATUS, CHECKINGSTATUS, CONTEXTSTATUS, SECMAINTSTATUS, SYSADMINSTATUS, VALIDATESTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for AUDITSTATUS, CHECKINGSTATUS, CONTEXTSTATUS, SECMAINTSTATUS, SYSMADMINSTATUS and VALIDATESTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES SECMAINT STATUS BOTH, VALIDATE STATUS BOTH, CHECKING STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement.  Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14956r295254_chk'
  tag severity: 'medium'
  tag gid: 'V-213735'
  tag rid: 'SV-213735r879863_rule'
  tag stig_id: 'DB2X-00-009600'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-14954r295255_fix'
  tag 'documentable'
  tag legacy: ['SV-89287', 'V-74613']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
