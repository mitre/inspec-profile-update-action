control 'SV-24442' do
  title 'Changes to DBMS security labels should be audited.'
  desc 'Some DBMS systems provide the feature to assign security labels to data elements. If labeling is required, implementation options include the Oracle Label Security package, or a third-party product, or custom-developed functionality.  The confidentiality and integrity of the data depends upon the security label assignment where this feature is in use. Changes to security label assignment may indicate suspicious activity.'
  desc 'check', 'If no data is identified as being sensitive or classified by the Information Owner, in the System Security Plan or in the AIS Functional Architecture documentation, this is not a finding.

If security labeling is not required, this is not a finding.

If no sensitive or classified data is identified by the Information Owner as requiring labeling in the System Security Plan and/or AIS Functional Architecture documentation, this is not a finding.

Run the SQL statement:
select * from dba_sa_audit_options;

If no records are returned or if output from the SQL statement above does not show classification labels being audited as required in the System Security Plan, this is a finding.'
  desc 'fix', 'Define the policy for auditing changes to security labels defined for the data.

Document the audit requirements in the System Security Plan and configure database auditing in accordance with the policy.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29386r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15657'
  tag rid: 'SV-24442r2_rule'
  tag stig_id: 'DG0172-ORACLE11'
  tag gtitle: 'DBMS classification level audit'
  tag fix_id: 'F-26412r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
