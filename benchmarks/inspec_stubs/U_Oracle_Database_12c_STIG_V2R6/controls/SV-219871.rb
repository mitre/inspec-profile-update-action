control 'SV-219871' do
  title 'Changes to DBMS security labels must be audited.'
  desc 'Some DBMS systems provide the feature to assign security labels to data elements. If labeling is required, implementation options include the Oracle Label Security package, or a third-party product, or custom-developed functionality.  The confidentiality and integrity of the data depends upon the security label assignment where this feature is in use. Changes to security label assignment may indicate suspicious activity.'
  desc 'check', %q(If no data has been identified as being sensitive or classified in the system documentation, this is not a finding.

If security labeling is not required, this is not a finding.

If Standard Auditing is used, run the SQL query:

select * from dba_sa_audit_options;

If no records are returned or if output from the SQL statement above does not show classification labels being audited as required in the System Security Plan, this is a finding.

If Unified Auditing is used:
To see if Oracle is configured to capture audit data including changes to security label assignment, enter the following SQL*Plus command:
SELECT 'Changes to security label assignment is not being audited. ' 
FROM   dual 
WHERE  (SELECT Count(*)
        FROM   (select policy_name , audit_option from audit_unified_policies
        WHERE  audit_option = 'ALL'
	  AND audit_option_type = 'OLS ACTION'
        AND policy_name in (select policy_name from audit_unified_enabled_policies where user_name='ALL USERS'))) = 0
        OR (SELECT value 
            FROM   v$option 
            WHERE  parameter = 'Unified Auditing') != 'TRUE';  

If Oracle returns "no rows selected", this is not a finding.

To confirm that Oracle audit is capturing sufficient information to establish that changes to classification labels are being audited, perform a successful auditable action and an auditable action that results in an SQL error, and then view the results in the SYS.UNIFIED_AUDIT_TRAIL view.

If no ACTION#, or the wrong value, is returned for the auditable actions, this is a finding.)
  desc 'fix', 'Define the policy for auditing changes to security labels defined for the data.

Document the audit requirements in the System Security Plan and configure database auditing in accordance with the policy.

If using Standard Auditing:
If there is no Unified Auditing policy deployed to audit changes to security labels, the create one using the following syntax:
SA_AUDIT_ADMIN.AUDIT (
     policy_name     IN VARCHAR2,
     users           IN VARCHAR2 DEFAULT NULL,
     audit_option    IN VARCHAR2 DEFAULT NULL,
     audit_type      IN VARCHAR2 DEFAULT NULL,
     success         IN VARCHAR2 DEFAULT NULL);

For additional information on creating audit policies, refer to the Oracle Database Security Guide
http://docs.oracle.com/database/121/OLSAG/packages.htm#i1011868

If Unified Auditing is used:
To ensure auditable events are captured:
Link the oracle binary with uniaud_on, and then restart the database. Oracle Database Upgrade Guide describes how to enable unified auditing.
Reference V-61625 for information on how to configure a policy to audit changes to security label assignments.

For additional information on creating audit policies, refer to the Oracle Database Security Guide
http://docs.oracle.com/database/121/DBSEG/audit_config.htm#CHDGBAAC'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21582r799971_chk'
  tag severity: 'medium'
  tag gid: 'V-219871'
  tag rid: 'SV-219871r799972_rule'
  tag stig_id: 'O121-BP-026200'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21581r533127_fix'
  tag 'documentable'
  tag legacy: ['SV-76017', 'V-61527']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
