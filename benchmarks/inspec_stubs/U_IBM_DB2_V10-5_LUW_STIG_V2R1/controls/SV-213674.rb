control 'SV-213674' do
  title 'DB2 must provide audit record generation capability for DoD-defined auditable events within all DBMS/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', "To meet these requirements, at the minimum AUDIT, CHECKING, CONTEXT, SECMAINT, SYSADMIN, and VALIDATE category auditing need to be implemented at the database level. 

Run the following SQL statement to ensure that an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ') 

If no rows are returned, this is a finding. 

Using the AUDITPOLICYID from the query above find the details of the audit policy. 
DB2> SELECT AUDITPOLICYNAME, AUDITSTATUS, CHECKINGSTATUS, CONTEXTSTATUS, SECMAINTSTATUS, SYSADMINSTATUS, VALIDATESTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for AUDITSTATUS, CHECKINGSTATUS, CONTEXTSTATUS, SECMAINTSTATUS, SYSMADMINSTATUS and VALIDATESTATUS  are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Define an audit policy using the CREATE AUDIT POLICY SQL statement:
DB2> CREATE AUDIT POLICY <DB audit policy name> CATEGORIES AUDIT STATUS BOTH, SYSADMIN STATUS BOTH, SECMAINT STATUS BOTH, VALIDATE STATUS BOTH, CHECKING STATUS BOTH, CONTEXT STATUS BOTH ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, apply the policy created above to the database:
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14895r295071_chk'
  tag severity: 'medium'
  tag gid: 'V-213674'
  tag rid: 'SV-213674r879559_rule'
  tag stig_id: 'DB2X-00-000600'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-14893r295072_fix'
  tag 'documentable'
  tag legacy: ['SV-89111', 'V-74437']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
