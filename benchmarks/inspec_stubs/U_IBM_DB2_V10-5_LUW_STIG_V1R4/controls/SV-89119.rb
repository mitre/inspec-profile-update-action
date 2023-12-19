control 'SV-89119' do
  title 'DB2 must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To be sure of capturing all activity during those periods when session auditing is in use, it needs to be in operation for the whole time the DBMS is running."
  desc 'check', "Determine whether there are any individuals for whom the organization requires session auditing.  If there are none, this is not a finding.

Type in the following command to check whether or not the user under investigation  is being audited:
DB2> SELECT AUDITPOLICYNAME, OBJECTNAME, OBJECTTYPE 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN ('i',' ')

If no rows are returned, this is a finding. 

If a row with the OBJECTTYPE of ' ' (Database; value is a blank) exists in the output, it is a database level policy. 

If a row with the OBJECTTYPE of 'i' exists in the output, it is a user level policy. 

For each audit policy returned in the statement above, run the following SQL statement to confirm that all categories are part of that policy:
DB2> SELECT * FROM SYSCAT.AUDITPOLICIES

If there is an audit policy defined at the database level with the values for the all the audit category columns set to 'B' (Both) and the value in the ERRORTYPE column set to 'A' (Audit), EXECUTEWITHDATA to 'Y' this is not a finding.

If the database policy does not exist or does not cover all the categories with ERRORTYPE column set to 'A' (Audit), EXECUTEWITHDATA to 'Y' then check if the appropriate policies are defined for all the required users. 

If the audit policy is defined on the users under investigation and does not have the values for all the audit category columns set to 'B' (Both) and the value in the ERRORTYPE column set to 'A' (Audit), EXECUTEWITHDATA to 'Y', this is a finding."
  desc 'fix', 'Define an audit policy using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <user audit policy name>
CATEGORIES AUDIT STATUS BOTH, CHECKING STATUS BOTH, CONTEXT STATUS BOTH, EXECUTE WITH DATA STATUS BOTH, OBJMAINT STATUS BOTH, SECMAINT STATUS BOTH, SYSADMIN STATUS BOTH, VALIDATE STATUS BOTH ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, apply the correct audit policy to either the database as a whole or to the specific user using one of these two statements:
DB2> AUDIT DATABASE USING POLICY <user audit policy name>
  Or 
DB2> AUDIT USER <user name> USING POLICY <user audit policy name>

Note: This requirement is to audit suspicious user activity. For a targeted session activity use the AUDIT USER command after the policy has been created. For a general database level use the AUDIT DATABASE command.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74371r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74445'
  tag rid: 'SV-89119r1_rule'
  tag stig_id: 'DB2X-00-001000'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-81045r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
