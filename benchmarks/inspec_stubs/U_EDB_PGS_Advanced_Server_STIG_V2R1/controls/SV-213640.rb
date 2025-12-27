control 'SV-213640' do
  title 'Audit records must be generated  when unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

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
  tag check_id: 'C-14862r290232_chk'
  tag severity: 'medium'
  tag gid: 'V-213640'
  tag rid: 'SV-213640r508024_rule'
  tag stig_id: 'PPS9-00-010300'
  tag gtitle: 'SRG-APP-000494-DB-000345'
  tag fix_id: 'F-14860r290233_fix'
  tag 'documentable'
  tag legacy: ['SV-83637', 'V-69033']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
