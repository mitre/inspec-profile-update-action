control 'SV-213681' do
  title 'Unless it has been determined that availability is paramount, DB2 must, upon audit failure, cease all auditable activity.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When the need for system availability does not outweigh the need for a complete audit trail, the DBMS should cease production of audit records immediately, rolling back all in-flight transactions.  DB2 does this when  configured to track audit errors.

Systems where audit trail completeness is paramount will most likely be at a lower MAC level than MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid a shutdown in all but the most extreme situations.'
  desc 'check', "Ask the ISSO whether the system should stay available or stop processing the auditable events.

If the system needs to stay available and the Error Type is set to 'A' for the policies then this is not applicable (NA).

Run the following SQL statement to find the Error type value for all audit policies:
DB2> SELECT * FROM SYSCAT.AUDITPOLICIES

If the system needs to stop processing the auditable events and Error Type is not set to 'A' then this is a finding."
  desc 'fix', 'Drop and recreate the policy with ERROR TYPE as required by the ISSO or run the ALTER AUDIT POLICY command to set the ERROR TYPE as per ISSO requirement. 

Run the following command to drop and recreate the policy:
DB2> DROP AUDIT POLICY <audit2>
DB2> CREATE AUDIT POLICY <audit2> 
          CATEGORIES EXECUTE WITH DATA STATUS BOTH ERROR TYPE AUDIT

To alter the audit policy:
DB2> ALTER AUDIT POLICY <audit2> 
          CATEGORIES EXECUTE WITH DATA STATUS BOTH ERROR TYPE AUDIT'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14902r295092_chk'
  tag severity: 'medium'
  tag gid: 'V-213681'
  tag rid: 'SV-213681r879571_rule'
  tag stig_id: 'DB2X-00-001900'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag fix_id: 'F-14900r295093_fix'
  tag 'documentable'
  tag legacy: ['SV-89125', 'V-74451']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
