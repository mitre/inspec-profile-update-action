control 'SV-89307' do
  title 'DB2 must generate audit records when categorized information (e.g., classification levels/security levels) is modified.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', "Review the system documentation to determine whether it is required to track categories of information, such as classification or sensitivity level. If it is not, this is not applicable (NA).

To meet these requirements at the SECMAINT, CONTEXT category auditing needs to be implemented at database level. 

Run the following SQL statement to ensure that an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ')

If no rows are returned, this is a finding. 

Using the AUDITPOLICYID from above query find the details of audit policy: 
DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, SECMAINTSTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for CONTEXTSTATUS and SECMAINTSTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES SECMAINT STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74519r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74633'
  tag rid: 'SV-89307r1_rule'
  tag stig_id: 'DB2X-00-010600'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag fix_id: 'F-81233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
