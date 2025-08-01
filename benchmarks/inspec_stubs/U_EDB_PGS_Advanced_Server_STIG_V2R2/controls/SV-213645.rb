control 'SV-213645' do
  title 'Audit records must be generated when categorized information (e.g., classification levels/security levels) is created.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'Review the system documentation to determine whether it is required to track categorized information, such as classification or sensitivity level. If it is not, this is not applicable (NA).
	
Execute the following SQL as enterprisedb:
	
SHOW edb_audit_statement;
	
If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:
	
ALTER SYSTEM SET edb_audit_statement = 'all';
SELECT pg_reload_conf();
	
or
	
Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14867r290247_chk'
  tag severity: 'medium'
  tag gid: 'V-213645'
  tag rid: 'SV-213645r508024_rule'
  tag stig_id: 'PPS9-00-011000'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag fix_id: 'F-14865r290248_fix'
  tag 'documentable'
  tag legacy: ['SV-83647', 'V-69043']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
