control 'SV-213655' do
  title 'The EDB Postgres Advanced Server must generate audit records when successful logons or connections occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to the DBMS.'
  desc 'check', 'Execute the following SQL as enterprisedb:
	
SHOW edb_audit_connect;
	
If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', %q(Execute the following SQL as enterprisedb:
	
SHOW edb_audit_connect;
	
If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.
	
Fix Text: Execute the following SQL as enterprisedb:
	
ALTER SYSTEM SET edb_audit_connect = 'all';
ALTER SYSTEM SET edb_audit_disconnect = 'all';
SELECT pg_reload_conf();   
	
or
	
Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement.)
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14877r290277_chk'
  tag severity: 'medium'
  tag gid: 'V-213655'
  tag rid: 'SV-213655r508024_rule'
  tag stig_id: 'PPS9-00-011800'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-14875r290278_fix'
  tag 'documentable'
  tag legacy: ['V-69059', 'SV-83663']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
