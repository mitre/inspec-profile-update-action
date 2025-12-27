control 'SV-213739' do
  title 'DB2 must generate audit records when privileges/permissions are added.'
  desc "Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of individuals' and groups' privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, adding permissions is typically done via the GRANT command."
  desc 'check', "To verify the database generates audit records when privileges/permissions are added is accessed the SECMAINT, CONTEXT category auditing must be implemented at the database level. 

Run the following SQL statement to ensure that an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ')

If no rows are returned, this is a finding. 

Run the following SQL statement using the AUDITPOLICYID from query above to find the details of the audit policy: 
DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, SECMAINTSTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for CONTEXTSTATUS and SECMAINTSTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES SECMAINT STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement.  Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14960r295266_chk'
  tag severity: 'medium'
  tag gid: 'V-213739'
  tag rid: 'SV-213739r879866_rule'
  tag stig_id: 'DB2X-00-010000'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag fix_id: 'F-14958r295267_fix'
  tag 'documentable'
  tag legacy: ['SV-89295', 'V-74621']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
