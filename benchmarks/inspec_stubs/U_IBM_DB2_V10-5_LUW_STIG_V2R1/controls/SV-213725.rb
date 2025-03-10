control 'SV-213725' do
  title 'DB2 must produce audit records of its enforcement of access restrictions associated with changes to the configuration of DB2 or database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', "To audit changes in configuration, the SYSADMIN category needs to be audited at both the instance level and the database level.

Run the following command to ensure that the SYSADMIN category is being audited at the instance level: 

     $db2audit describe

If Log system administrator events is not set to “Both”, this is a finding.

Run the following SQL statement to ensure that an audit policy exists at the database level: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE = ' '

If no rows are returned, this is a finding.

For the audit policy returned in the statement above, run the following SQL statement to confirm that the SYSADMIN category is part of that policy and the ERROR TYPE='A': 
DB2> SELECT AUDITPOLICYNAME, SYSADMINSTATUS, CONTEXTSTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for SYSADMINSTATUS and CONTEXTSTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Run the following command to set the auditing at the instance level: 

     $db2audit configure scope sysadmin status both error type audit

Run the following command to set the auditing at the database level: 
DB2> CREATE AUDIT POLICY <DB audit policy name> CATEGORIES SYSADMIN STATUS BOTH, CONTEXT STATUS BOTH ERROR TYPE AUDIT

Run the following command if the auditing policy exists but does not include the sysadmin category: 
DB2> ALTER AUDIT POLICY <DB audit policy name> SYSADMIN STATUS BOTH, CONTEXT STATUS BOTH ERROR TYPE AUDIT 

If CREATE was used above, apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>

Note: See the following page for knowledgebase information regarding the ALTER AUDIT POLICY: 
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0050608.html?lang=en'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14946r295224_chk'
  tag severity: 'medium'
  tag gid: 'V-213725'
  tag rid: 'SV-213725r879754_rule'
  tag stig_id: 'DB2X-00-008200'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-14944r295225_fix'
  tag 'documentable'
  tag legacy: ['SV-89267', 'V-74593']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
