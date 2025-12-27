control 'SV-89305' do
  title 'DB2 must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "If there are no locally defined security objects this is not applicable (NA).

If there are locally defined security objects get a list of those objects from ISSO/DBA.

If there are only tables in the list then a minimum audit set of OBJMAINT and SECMAINT categories on the locally defined security tables or database is required.

If there are objects like packages and procedures in the list of locally defined security objects then a minimum audit set of OBJMAINT and SECMAINT categories on the database is required.

Run the following SQL statement to ensure that an audit policy is defined upon the database:
DB2> SELECT AUDITPOLICYNAME, OBJECTSCHEMA, OBJECTNAME, OBJECTTYPE 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN ('T',' ')

If no rows are returned, this is a finding. 

If a row with OBJECTTYPE of ' ' (Database; value is a blank) exists in the output, it is a database level policy. 

If a row with OBJECTTYPE of 'T' exists in the output, it is a table level policy. 

For each audit policy returned in the statement above, run the following SQL statement to confirm that the OBJMAINT and SECMAINT categories are part of that policy: 
DB2> SELECT AUDITPOLICYNAME, SECMAINTSTATUS, OBJMAINTSTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES

If the database audit policy has the values for the SECMAINTSTATUS and OBJMAINTSTATUS columns set to 'F' (Failure) or 'B' (Both) and the value in the ERRORTYPE column set to 'A' (Audit), this is not a finding. 

If there are objects in additions to tables in the list of locally defined security objects and if the database policy does not exist or does not cover SECMAINTSTATUS or OBJMAINTSTATUS, this is a finding. 

If there are only tables in the list and if the database policy does not exist or does not cover SECMAINTSTATUS or OBJMAINTSTATUS then check if the appropriate policies are defined for all the required locally defined security tables. 

If any of the required locally defined security tables' audit policies do not have the values for the SECMAINTSTATUS  and OBJMAINTSTATUS columns set to  'F' (Failure) or 'B' (Both) or the value in the ERRORTYPE column set to 'A' (Audit), then this is a finding."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement:
DB2> CREATE AUDIT POLICY <execdb> CATEGORIES OBJMAINT STATUS SUCCESS, SECMAINT STATUS BOTH ERROR TYPE AUDIT
             or
           CREATE AUDIT POLICY <execdb> CATEGORIES OBJMAINT STATUS SUCCESS, SECMAINT STATUS FAILURE ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the correct policy to local security tables or database level:
DB2> AUDIT TABLE <table name> USING POLICY EXECDB'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74517r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74631'
  tag rid: 'SV-89305r1_rule'
  tag stig_id: 'DB2X-00-010500'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-81231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
