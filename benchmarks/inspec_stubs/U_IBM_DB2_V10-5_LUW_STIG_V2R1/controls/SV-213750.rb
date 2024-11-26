control 'SV-213750' do
  title 'DB2 must generate audit records when unsuccessful attempts to delete security objects occur.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an action is attempted, it must be logged.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', "To meet these requirements at the SECMAINT, OBJMAINT, and CONTEXT categories, auditing need to be implemented at the database level. 

Run the following SQL statement to ensure that an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ')

If no rows are returned, this is a finding. 

Using the AUDITPOLICYID from above query find the details of audit policy: 
DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, SECMAINTSTATUS, OBJMAINTSTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for CONTEXTSTATUS, OBJMAINTSTATUS and SECMAINTSTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES SECMAINT STATUS BOTH, OBJMAINTSTATUS STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14971r295299_chk'
  tag severity: 'medium'
  tag gid: 'V-213750'
  tag rid: 'SV-213750r879872_rule'
  tag stig_id: 'DB2X-00-011100'
  tag gtitle: 'SRG-APP-000501-DB-000337'
  tag fix_id: 'F-14969r295300_fix'
  tag 'documentable'
  tag legacy: ['SV-89323', 'V-74649']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
